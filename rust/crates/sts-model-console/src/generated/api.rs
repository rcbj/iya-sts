// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// What the console draws around every page, for this caller
pub mod get_console_shell {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console";
    pub const OPERATION_ID: &str = "getConsoleShell";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogs: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GateBootstrap {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seeded: Option<bool>,
        #[serde(rename = "claimedAt", default, skip_serializing_if = "Option::is_none")]
        pub claimed_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Gate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub authority: Option<Option<String>>,
        #[serde(rename = "identityRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub identity_realm: Option<Option<String>>,
        #[serde(rename = "readGroup", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub read_group: Option<Option<String>>,
        #[serde(rename = "writeGroup", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub write_group: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub read: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub write: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub security: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub open: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub closed: Option<bool>,
        #[serde(rename = "windowOpens", default, skip_serializing_if = "Option::is_none")]
        pub window_opens: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub empty: Option<bool>,
        #[serde(rename = "bootstrapPasswordRequired", default, skip_serializing_if = "Option::is_none")]
        pub bootstrap_password_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bootstrap: Option<Answer200GateBootstrap>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Realm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Retiring {
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
    pub struct Answer200Runtime {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<String>,
        #[serde(rename = "keyEncryptionKey", default, skip_serializing_if = "Option::is_none")]
        pub key_encryption_key: Option<String>,
        #[serde(rename = "databasePassword", default, skip_serializing_if = "Option::is_none")]
        pub database_password: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Persistence {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Version {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stamped: Option<bool>,
        #[serde(rename = "buildInfo", default, skip_serializing_if = "Option::is_none")]
        pub build_info: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gate: Option<Answer200Gate>,
        #[serde(rename = "navAuthority", default, skip_serializing_if = "Option::is_none")]
        pub nav_authority: Option<String>,
        /// Each role the gate names, by its id.
        #[serde(rename = "roleLabels", default, skip_serializing_if = "Option::is_none")]
        pub role_labels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200Realm>,
        #[serde(rename = "wsTrustIssuer", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ws_trust_issuer: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realms: Option<Option<Vec<serde_json::Value>>>,
        #[serde(rename = "realmRoot", default, skip_serializing_if = "Option::is_none")]
        pub realm_root: Option<String>,
        #[serde(rename = "portalHref", default, skip_serializing_if = "Option::is_none")]
        pub portal_href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sections: Option<sts_model_console_components_3::WithLocaleChainCatalog>,
        /// Every console page's label, by its path.
        #[serde(rename = "navLabels", default, skip_serializing_if = "Option::is_none")]
        pub nav_labels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retiring: Option<Answer200Retiring>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub runtime: Option<Answer200Runtime>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persistence: Option<Answer200Persistence>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<Answer200Version>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locale: Option<sts_model_console_components_3::WithNegotiatedOfferedDescription>,
    }
}

/// What the console's API explorer reads, and what you may drive
pub mod get_api_explorer {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/api-explorer";
    pub const OPERATION_ID: &str = "getApiExplorer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub api: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub audience: Option<Option<String>>,
        #[serde(rename = "tokenInReply", default, skip_serializing_if = "Option::is_none")]
        pub token_in_reply: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub who: Option<String>,
        #[serde(rename = "realmPrefix", default, skip_serializing_if = "Option::is_none")]
        pub realm_prefix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub script: Option<String>,
    }
}

/// Mint a client secret for an application about to be created, writing nothing
pub mod generate_client_secret {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/console/applications/generate-secret";
    pub const OPERATION_ID: &str = "generateClientSecret";

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

    pub type Answer200 = sts_model_console_components_3::WithOkChangedClientSecret;
}

/// Everything the new application form is drawn from
pub mod get_console_new_application_form {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/applications/new";
    pub const OPERATION_ID: &str = "getConsoleNewApplicationForm";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Realm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KindsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProtocolsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
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
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeclarationsItemFamiliesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeclarationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub editable: Option<Option<sts_model_base::unions::BoolOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sensitive: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub families: Option<Vec<Answer200DeclarationsItemFamiliesItem>>,
        #[serde(rename = "everyFamily", default, skip_serializing_if = "Option::is_none")]
        pub every_family: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FieldsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub long: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub editable: Option<Option<sts_model_base::unions::BoolOrString>>,
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
        #[serde(rename = "inSimple", default, skip_serializing_if = "Option::is_none")]
        pub in_simple: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub described: Option<sts_model_console_components_3::WithKeyGroupLabel5>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FieldGroupsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub families: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FamilyChoicesItem {
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
    pub struct Answer200Persistence {
        #[serde(rename = "persistsDirectory", default, skip_serializing_if = "Option::is_none")]
        pub persists_directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub mode: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ResourceMetadataImport {
        #[serde(rename = "wellKnown", default, skip_serializing_if = "Option::is_none")]
        pub well_known: Option<String>,
        #[serde(rename = "acceptsNonconforming", default, skip_serializing_if = "Option::is_none")]
        pub accepts_nonconforming: Option<bool>,
        #[serde(rename = "dialsInternalAddresses", default, skip_serializing_if = "Option::is_none")]
        pub dials_internal_addresses: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EditableItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub mode: Option<Option<sts_model_base::unions::BoolOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sensitive: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub families: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub container: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub max: Option<Option<f64>>,
        #[serde(rename = "applicationCount", default, skip_serializing_if = "Option::is_none")]
        pub application_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200Realm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<Answer200KindsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<Answer200ProtocolsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub declarations: Option<Vec<Answer200DeclarationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Vec<Answer200FieldsItem>>,
        #[serde(rename = "fieldGroups", default, skip_serializing_if = "Option::is_none")]
        pub field_groups: Option<Vec<Answer200FieldGroupsItem>>,
        #[serde(rename = "familyChoices", default, skip_serializing_if = "Option::is_none")]
        pub family_choices: Option<Vec<Answer200FamilyChoicesItem>>,
        #[serde(rename = "longTextAttributes", default, skip_serializing_if = "Option::is_none")]
        pub long_text_attributes: Option<Vec<String>>,
        #[serde(rename = "defaultSecretLifetimeDays", default, skip_serializing_if = "Option::is_none")]
        pub default_secret_lifetime_days: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persistence: Option<Answer200Persistence>,
        #[serde(rename = "resourceMetadataImport", default, skip_serializing_if = "Option::is_none")]
        pub resource_metadata_import: Option<Answer200ResourceMetadataImport>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub editable: Option<Vec<Answer200EditableItem>>,
    }
}

/// What the console's front page draws
pub mod get_console_dashboard {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/dashboard";
    pub const OPERATION_ID: &str = "getConsoleDashboard";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Persistence {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issuer: Option<Option<String>>,
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
        pub started_at: Option<String>,
        #[serde(rename = "uptimeMs", default, skip_serializing_if = "Option::is_none")]
        pub uptime_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub calls: Option<f64>,
        #[serde(rename = "tokensHeld", default, skip_serializing_if = "Option::is_none")]
        pub tokens_held: Option<f64>,
        #[serde(rename = "tokensHeldOnly", default, skip_serializing_if = "Option::is_none")]
        pub tokens_held_only: Option<bool>,
        #[serde(rename = "tokensRevoked", default, skip_serializing_if = "Option::is_none")]
        pub tokens_revoked: Option<f64>,
        #[serde(rename = "artifactsHeld", default, skip_serializing_if = "Option::is_none")]
        pub artifacts_held: Option<f64>,
        #[serde(rename = "signOnSessions", default, skip_serializing_if = "Option::is_none")]
        pub sign_on_sessions: Option<f64>,
        #[serde(rename = "usersKnown", default, skip_serializing_if = "Option::is_none")]
        pub users_known: Option<f64>,
        #[serde(rename = "usersAuthenticatedHere", default, skip_serializing_if = "Option::is_none")]
        pub users_authenticated_here: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persistence: Option<Answer200Persistence>,
        #[serde(rename = "testDouble", default, skip_serializing_if = "Option::is_none")]
        pub test_double: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sections: Option<sts_model_console_components_3::WithLocaleChainCatalog>,
    }
}

/// The configured permissions register, as its page shows it
pub mod get_delegation_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation-settings";
    pub const OPERATION_ID: &str = "getDelegationSettings";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryType {
        #[serde(rename = "krb5-s4u2self")]
        Krb5S4u2self,
        #[serde(rename = "krb5-s4u2proxy-classic")]
        Krb5S4u2proxyClassic,
        #[serde(rename = "krb5-s4u2proxy-rbcd")]
        Krb5S4u2proxyRbcd,
        #[serde(rename = "krb5-forwarded")]
        Krb5Forwarded,
        #[serde(rename = "wstrust-onbehalfof")]
        WstrustOnbehalfof,
        #[serde(rename = "wstrust-actas")]
        WstrustActas,
        #[serde(rename = "oauth-impersonation")]
        OauthImpersonation,
        #[serde(rename = "oauth-delegation")]
        OauthDelegation,
        #[serde(rename = "oauth-assertion-grant")]
        OauthAssertionGrant,
        #[serde(rename = "oauth-saml-assertion-grant")]
        OauthSamlAssertionGrant,
        #[serde(rename = "gnap-impersonation")]
        GnapImpersonation,
        #[serde(rename = "gnap-derivation")]
        GnapDerivation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryMode {
        #[serde(rename = "impersonation")]
        Impersonation,
        #[serde(rename = "delegation")]
        Delegation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<QueryType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userfrom: Option<i64>,
        #[serde(rename = "chainsPage", default, skip_serializing_if = "Option::is_none")]
        pub chains_page: Option<i64>,
        #[serde(rename = "permissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub permissions_page: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "pairsPage", default, skip_serializing_if = "Option::is_none")]
        pub pairs_page: Option<i64>,
        #[serde(rename = "flagsPage", default, skip_serializing_if = "Option::is_none")]
        pub flags_page: Option<i64>,
        #[serde(rename = "mechanismsPage", default, skip_serializing_if = "Option::is_none")]
        pub mechanisms_page: Option<i64>,
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AllowedFilter {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub permissions: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub grants: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AllowedPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Allowed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<sts_model_console_components_3::WithResourcesPermissionsUnidentified>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<sts_model_console_components_3::WithKeyMembersCounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_console_components_3::WithPagePagesPerPage4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<sts_model_console_components_3::WithResourcesPermissionsUnidentified2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200AllowedFilter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200AllowedPaging>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SettingsGroupsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Vec<sts_model_console_components_3::WithKeyGroupLabel5>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SettingsContext {
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
    pub struct Answer200Settings {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<Answer200SettingsGroupsItem>>,
        #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
        pub setting_count: Option<i64>,
        #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
        pub editable_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub overridden: Option<Vec<String>>,
        #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
        pub set_with: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<Answer200SettingsContext>,
        /// The other pages a settings group is drawn on.
        #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
        pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListState {
        #[serde(rename = "permWanted", default, skip_serializing_if = "Option::is_none")]
        pub perm_wanted: Option<String>,
        #[serde(rename = "grantWanted", default, skip_serializing_if = "Option::is_none")]
        pub grant_wanted: Option<String>,
        #[serde(rename = "permPage", default, skip_serializing_if = "Option::is_none")]
        pub perm_page: Option<sts_model_console_components_3::WithShownPagingOnlyWhileOn>,
        #[serde(rename = "grantPage", default, skip_serializing_if = "Option::is_none")]
        pub grant_page: Option<sts_model_console_components_3::WithShownPagingShown>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AllApplicationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<Answer200Allowed>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Answer200Settings>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub register: Option<sts_model_console_components_3::WithResourcesPermissionsGrants>,
        #[serde(rename = "listState", default, skip_serializing_if = "Option::is_none")]
        pub list_state: Option<Answer200ListState>,
        #[serde(rename = "allApplications", default, skip_serializing_if = "Option::is_none")]
        pub all_applications: Option<Vec<Answer200AllApplicationsItem>>,
    }
}

/// The configured delegated permissions, drawn, and groups
pub mod get_delegation_allowed {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation/allowed";
    pub const OPERATION_ID: &str = "getDelegationAllowed";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryType {
        #[serde(rename = "krb5-s4u2self")]
        Krb5S4u2self,
        #[serde(rename = "krb5-s4u2proxy-classic")]
        Krb5S4u2proxyClassic,
        #[serde(rename = "krb5-s4u2proxy-rbcd")]
        Krb5S4u2proxyRbcd,
        #[serde(rename = "krb5-forwarded")]
        Krb5Forwarded,
        #[serde(rename = "wstrust-onbehalfof")]
        WstrustOnbehalfof,
        #[serde(rename = "wstrust-actas")]
        WstrustActas,
        #[serde(rename = "oauth-impersonation")]
        OauthImpersonation,
        #[serde(rename = "oauth-delegation")]
        OauthDelegation,
        #[serde(rename = "oauth-assertion-grant")]
        OauthAssertionGrant,
        #[serde(rename = "oauth-saml-assertion-grant")]
        OauthSamlAssertionGrant,
        #[serde(rename = "gnap-impersonation")]
        GnapImpersonation,
        #[serde(rename = "gnap-derivation")]
        GnapDerivation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryMode {
        #[serde(rename = "impersonation")]
        Impersonation,
        #[serde(rename = "delegation")]
        Delegation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<QueryType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userfrom: Option<i64>,
        #[serde(rename = "chainsPage", default, skip_serializing_if = "Option::is_none")]
        pub chains_page: Option<i64>,
        #[serde(rename = "permissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub permissions_page: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "pairsPage", default, skip_serializing_if = "Option::is_none")]
        pub pairs_page: Option<i64>,
        #[serde(rename = "flagsPage", default, skip_serializing_if = "Option::is_none")]
        pub flags_page: Option<i64>,
        #[serde(rename = "mechanismsPage", default, skip_serializing_if = "Option::is_none")]
        pub mechanisms_page: Option<i64>,
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupCounts {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::NodeSLookNodeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_console_components_3::WithRealmIssuerNodes4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<sts_model_console_components_3::WithResourcesPermissionsUnidentified2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_console_components_3::WithPagePagesPerPage4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<sts_model_console_components_3::WithAtFamilyKind2>,
        #[serde(rename = "groupCounts", default, skip_serializing_if = "Option::is_none")]
        pub group_counts: Option<Answer200GroupCounts>,
        #[serde(rename = "groupsPaging", default, skip_serializing_if = "Option::is_none")]
        pub groups_paging: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub register: Option<sts_model_console_components_3::WithResourcesPermissionsGrants>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clusters: Option<sts_model_console_components_3::WithClustersDescriptionMemberOf2>,
        #[serde(rename = "shownGroups", default, skip_serializing_if = "Option::is_none")]
        pub shown_groups: Option<sts_model_console_components_3::WithClustersDescriptionMemberOf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_console_components_3::WithDescriptionUsersDescription>,
        /// Each name in the answer the registry holds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub apps: Option<serde_json::Map<String, serde_json::Value>>,
    }
}

/// One application's delegations, drawn
pub mod get_console_delegation_application {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation/application";
    pub const OPERATION_ID: &str = "getConsoleDelegationApplication";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryType {
        #[serde(rename = "krb5-s4u2self")]
        Krb5S4u2self,
        #[serde(rename = "krb5-s4u2proxy-classic")]
        Krb5S4u2proxyClassic,
        #[serde(rename = "krb5-s4u2proxy-rbcd")]
        Krb5S4u2proxyRbcd,
        #[serde(rename = "krb5-forwarded")]
        Krb5Forwarded,
        #[serde(rename = "wstrust-onbehalfof")]
        WstrustOnbehalfof,
        #[serde(rename = "wstrust-actas")]
        WstrustActas,
        #[serde(rename = "oauth-impersonation")]
        OauthImpersonation,
        #[serde(rename = "oauth-delegation")]
        OauthDelegation,
        #[serde(rename = "oauth-assertion-grant")]
        OauthAssertionGrant,
        #[serde(rename = "oauth-saml-assertion-grant")]
        OauthSamlAssertionGrant,
        #[serde(rename = "gnap-impersonation")]
        GnapImpersonation,
        #[serde(rename = "gnap-derivation")]
        GnapDerivation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryMode {
        #[serde(rename = "impersonation")]
        Impersonation,
        #[serde(rename = "delegation")]
        Delegation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<QueryType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userfrom: Option<i64>,
        #[serde(rename = "chainsPage", default, skip_serializing_if = "Option::is_none")]
        pub chains_page: Option<i64>,
        #[serde(rename = "permissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub permissions_page: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "pairsPage", default, skip_serializing_if = "Option::is_none")]
        pub pairs_page: Option<i64>,
        #[serde(rename = "flagsPage", default, skip_serializing_if = "Option::is_none")]
        pub flags_page: Option<i64>,
        #[serde(rename = "mechanismsPage", default, skip_serializing_if = "Option::is_none")]
        pub mechanisms_page: Option<i64>,
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicationRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Application {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spellings: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Answer200ApplicationRoles>,
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
        #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
        pub first_at: Option<f64>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
        #[serde(rename = "identityKey", default, skip_serializing_if = "Option::is_none")]
        pub identity_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicationsItemRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spellings: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Answer200ApplicationsItemRoles>,
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
        #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
        pub first_at: Option<f64>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
        #[serde(rename = "identityKey", default, skip_serializing_if = "Option::is_none")]
        pub identity_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RolesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::NodeSLookNodeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<Answer200Application>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub asked: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub registered: Option<bool>,
        #[serde(rename = "registeredName", default, skip_serializing_if = "Option::is_none")]
        pub registered_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<sts_model_console_components_3::WithIdLabelCa2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_console_components_3::WithRealmIssuerNodes4>,
        /// The roles played, by the act's `seq`.
        #[serde(rename = "rolesBySeq", default, skip_serializing_if = "Option::is_none")]
        pub roles_by_seq: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<Vec<Answer200ApplicationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<i64>,
        #[serde(rename = "maxRecords", default, skip_serializing_if = "Option::is_none")]
        pub max_records: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<Answer200RolesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chooser: Option<sts_model_console_components_3::WithTotalEntriesKey2>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_console_components_3::WithDescriptionUsersDescription>,
    }
}

/// One delegation relationship: its acts, graph and drawing
pub mod get_delegation_chain {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation/chain";
    pub const OPERATION_ID: &str = "getDelegationChain";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ChainInitial {
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
    pub struct Answer200ChainIntermediary {
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
    pub struct Answer200ChainTarget {
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
    pub struct Answer200Chain {
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
        pub initial: Option<Answer200ChainInitial>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<Answer200ChainIntermediary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<Answer200ChainTarget>,
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
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::NodeSLookNodeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<Answer200Chain>,
        #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
        pub chain_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<sts_model_console_components_3::WithIdLabelCa2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_console_components_3::WithRealmIssuerNodes4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<i64>,
        #[serde(rename = "maxRecords", default, skip_serializing_if = "Option::is_none")]
        pub max_records: Option<i64>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_console_components_3::WithDescriptionUsersDescription>,
    }
}

/// One group of applications joined by permissions, drawn
pub mod get_delegation_cluster {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation/cluster";
    pub const OPERATION_ID: &str = "getDelegationCluster";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryType {
        #[serde(rename = "krb5-s4u2self")]
        Krb5S4u2self,
        #[serde(rename = "krb5-s4u2proxy-classic")]
        Krb5S4u2proxyClassic,
        #[serde(rename = "krb5-s4u2proxy-rbcd")]
        Krb5S4u2proxyRbcd,
        #[serde(rename = "krb5-forwarded")]
        Krb5Forwarded,
        #[serde(rename = "wstrust-onbehalfof")]
        WstrustOnbehalfof,
        #[serde(rename = "wstrust-actas")]
        WstrustActas,
        #[serde(rename = "oauth-impersonation")]
        OauthImpersonation,
        #[serde(rename = "oauth-delegation")]
        OauthDelegation,
        #[serde(rename = "oauth-assertion-grant")]
        OauthAssertionGrant,
        #[serde(rename = "oauth-saml-assertion-grant")]
        OauthSamlAssertionGrant,
        #[serde(rename = "gnap-impersonation")]
        GnapImpersonation,
        #[serde(rename = "gnap-derivation")]
        GnapDerivation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryMode {
        #[serde(rename = "impersonation")]
        Impersonation,
        #[serde(rename = "delegation")]
        Delegation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<QueryType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userfrom: Option<i64>,
        #[serde(rename = "chainsPage", default, skip_serializing_if = "Option::is_none")]
        pub chains_page: Option<i64>,
        #[serde(rename = "permissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub permissions_page: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "pairsPage", default, skip_serializing_if = "Option::is_none")]
        pub pairs_page: Option<i64>,
        #[serde(rename = "flagsPage", default, skip_serializing_if = "Option::is_none")]
        pub flags_page: Option<i64>,
        #[serde(rename = "mechanismsPage", default, skip_serializing_if = "Option::is_none")]
        pub mechanisms_page: Option<i64>,
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Group {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<sts_model_console_components_3::WithApplicationsGrantsLines3>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
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
    pub struct Answer200Cluster {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_console_components_3::WithPagePagesPerPage4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<sts_model_console_components_3::WithKeyMembersCounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<sts_model_console_components_3::WithApplicationsGrantsLines3>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupPage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<sts_model_console_components_3::WithClustersDescriptionMemberOf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::NodeSLookNodeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub application: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<Answer200Group>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_console_components_3::WithPagePagesPerPage4>,
        #[serde(rename = "grantsPaging", default, skip_serializing_if = "Option::is_none")]
        pub grants_paging: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<sts_model_console_components_3::WithKeyMembersCounts>,
        #[serde(rename = "permissionsPaging", default, skip_serializing_if = "Option::is_none")]
        pub permissions_paging: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<sts_model_console_components_3::WithAtFamilyKind2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_console_components_3::WithPagePagesPerPage5>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_console_components_3::WithRealmIssuerNodes4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cluster: Option<Answer200Cluster>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub register: Option<sts_model_console_components_3::WithResourcesPermissionsGrants>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clusters: Option<sts_model_console_components_3::WithClustersDescriptionMemberOf2>,
        #[serde(rename = "grantPage", default, skip_serializing_if = "Option::is_none")]
        pub grant_page: Option<sts_model_console_components_3::WithShownPagingShown>,
        #[serde(rename = "permissionPage", default, skip_serializing_if = "Option::is_none")]
        pub permission_page: Option<sts_model_console_components_3::WithShownPagingOnlyWhileOn>,
        #[serde(rename = "groupPage", default, skip_serializing_if = "Option::is_none")]
        pub group_page: Option<Answer200GroupPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_console_components_3::WithDescriptionUsersDescription>,
        /// Each name in the answer the registry holds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub apps: Option<serde_json::Map<String, serde_json::Value>>,
    }
}

/// The delegation picture: the graph, each box, the drawing
pub mod get_delegation_map {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation/map";
    pub const OPERATION_ID: &str = "getDelegationMap";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryType {
        #[serde(rename = "krb5-s4u2self")]
        Krb5S4u2self,
        #[serde(rename = "krb5-s4u2proxy-classic")]
        Krb5S4u2proxyClassic,
        #[serde(rename = "krb5-s4u2proxy-rbcd")]
        Krb5S4u2proxyRbcd,
        #[serde(rename = "krb5-forwarded")]
        Krb5Forwarded,
        #[serde(rename = "wstrust-onbehalfof")]
        WstrustOnbehalfof,
        #[serde(rename = "wstrust-actas")]
        WstrustActas,
        #[serde(rename = "oauth-impersonation")]
        OauthImpersonation,
        #[serde(rename = "oauth-delegation")]
        OauthDelegation,
        #[serde(rename = "oauth-assertion-grant")]
        OauthAssertionGrant,
        #[serde(rename = "oauth-saml-assertion-grant")]
        OauthSamlAssertionGrant,
        #[serde(rename = "gnap-impersonation")]
        GnapImpersonation,
        #[serde(rename = "gnap-derivation")]
        GnapDerivation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryMode {
        #[serde(rename = "impersonation")]
        Impersonation,
        #[serde(rename = "delegation")]
        Delegation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<QueryType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userfrom: Option<i64>,
        #[serde(rename = "chainsPage", default, skip_serializing_if = "Option::is_none")]
        pub chains_page: Option<i64>,
        #[serde(rename = "permissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub permissions_page: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "pairsPage", default, skip_serializing_if = "Option::is_none")]
        pub pairs_page: Option<i64>,
        #[serde(rename = "flagsPage", default, skip_serializing_if = "Option::is_none")]
        pub flags_page: Option<i64>,
        #[serde(rename = "mechanismsPage", default, skip_serializing_if = "Option::is_none")]
        pub mechanisms_page: Option<i64>,
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Realm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
        pub is_default: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
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
    pub struct Answer200Summary {
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
        pub chains: Option<i64>,
        #[serde(rename = "oldestSeq", default, skip_serializing_if = "Option::is_none")]
        pub oldest_seq: Option<f64>,
        #[serde(rename = "newestSeq", default, skip_serializing_if = "Option::is_none")]
        pub newest_seq: Option<f64>,
        /// Acts per mechanism.
        #[serde(rename = "byType", default, skip_serializing_if = "Option::is_none")]
        pub by_type: Option<serde_json::Map<String, serde_json::Value>>,
        /// Acts per mode.
        #[serde(rename = "byMode", default, skip_serializing_if = "Option::is_none")]
        pub by_mode: Option<serde_json::Map<String, serde_json::Value>>,
        /// Acts per outcome.
        #[serde(rename = "byOutcome", default, skip_serializing_if = "Option::is_none")]
        pub by_outcome: Option<serde_json::Map<String, serde_json::Value>>,
        /// Acts per protocol.
        #[serde(rename = "byProtocol", default, skip_serializing_if = "Option::is_none")]
        pub by_protocol: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TypesItem {
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
    pub struct Answer200ModesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::NodeSLookNodeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200Realm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<sts_model_console_components_3::WithKindCountIdentifiers2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub edges: Option<sts_model_console_components_3::WithSeqAtKind3>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tokens: Option<sts_model_console_components_3::WithTotalEntriesKey>,
        #[serde(rename = "tokensLeftOff", default, skip_serializing_if = "Option::is_none")]
        pub tokens_left_off: Option<i64>,
        #[serde(rename = "maxTokenRows", default, skip_serializing_if = "Option::is_none")]
        pub max_token_rows: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<Answer200Summary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub all: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub types: Option<Vec<Answer200TypesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub modes: Option<Vec<Answer200ModesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcomes: Option<Vec<String>>,
        #[serde(rename = "applicationChooser", default, skip_serializing_if = "Option::is_none")]
        pub application_chooser: Option<sts_model_console_components_3::WithTotalEntriesKey2>,
        #[serde(rename = "userChooser", default, skip_serializing_if = "Option::is_none")]
        pub user_chooser: Option<sts_model_console_components_3::WithTotalEntriesKey2>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
        #[serde(rename = "directoryLoaded", default, skip_serializing_if = "Option::is_none")]
        pub directory_loaded: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_console_components_3::WithDescriptionUsersDescription>,
    }
}

/// One person's delegations, drawn
pub mod get_console_delegation_user {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/delegation/user";
    pub const OPERATION_ID: &str = "getConsoleDelegationUser";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryType {
        #[serde(rename = "krb5-s4u2self")]
        Krb5S4u2self,
        #[serde(rename = "krb5-s4u2proxy-classic")]
        Krb5S4u2proxyClassic,
        #[serde(rename = "krb5-s4u2proxy-rbcd")]
        Krb5S4u2proxyRbcd,
        #[serde(rename = "krb5-forwarded")]
        Krb5Forwarded,
        #[serde(rename = "wstrust-onbehalfof")]
        WstrustOnbehalfof,
        #[serde(rename = "wstrust-actas")]
        WstrustActas,
        #[serde(rename = "oauth-impersonation")]
        OauthImpersonation,
        #[serde(rename = "oauth-delegation")]
        OauthDelegation,
        #[serde(rename = "oauth-assertion-grant")]
        OauthAssertionGrant,
        #[serde(rename = "oauth-saml-assertion-grant")]
        OauthSamlAssertionGrant,
        #[serde(rename = "gnap-impersonation")]
        GnapImpersonation,
        #[serde(rename = "gnap-derivation")]
        GnapDerivation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryMode {
        #[serde(rename = "impersonation")]
        Impersonation,
        #[serde(rename = "delegation")]
        Delegation,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<QueryType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userfrom: Option<i64>,
        #[serde(rename = "chainsPage", default, skip_serializing_if = "Option::is_none")]
        pub chains_page: Option<i64>,
        #[serde(rename = "permissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub permissions_page: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "pairsPage", default, skip_serializing_if = "Option::is_none")]
        pub pairs_page: Option<i64>,
        #[serde(rename = "flagsPage", default, skip_serializing_if = "Option::is_none")]
        pub flags_page: Option<i64>,
        #[serde(rename = "mechanismsPage", default, skip_serializing_if = "Option::is_none")]
        pub mechanisms_page: Option<i64>,
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UserTokens {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub other: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UserRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200User {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presented: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forms: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authenticated: Option<bool>,
        #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
        pub is_client: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tokens: Option<Answer200UserTokens>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub artifacts: Option<i64>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Answer200UserRoles>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FlowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flow: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub oidc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub browser: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unknown: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UsersItemTokens {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub other: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UsersItemRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UsersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presented: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forms: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authenticated: Option<bool>,
        #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
        pub is_client: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tokens: Option<Answer200UsersItemTokens>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub artifacts: Option<i64>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
        pub last_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Answer200UsersItemRoles>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::NodeSLookNodeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<Answer200User>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub asked: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<sts_model_console_components_3::WithRealmIssuerNodes3>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flows: Option<Vec<Answer200FlowsItem>>,
        #[serde(rename = "onDelegationLines", default, skip_serializing_if = "Option::is_none")]
        pub on_delegation_lines: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<sts_model_console_components_3::WithIdLabelCa2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_console_components_3::WithRealmIssuerNodes4>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<Vec<Answer200UsersItem>>,
        #[serde(rename = "usersComplete", default, skip_serializing_if = "Option::is_none")]
        pub users_complete: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chooser: Option<sts_model_console_components_3::WithTotalEntriesKey2>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_console_components_3::WithDescriptionUsersDescription>,
    }
}

/// This realm's federation relationships, drawn
pub mod get_federation_map {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/federation/map";
    pub const OPERATION_ID: &str = "getFederationMap";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "svg")]
        Svg,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Realm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
        pub is_default: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationships: Option<i64>,
        #[serde(rename = "serviceProvider", default, skip_serializing_if = "Option::is_none")]
        pub service_provider: Option<i64>,
        #[serde(rename = "identityProvider", default, skip_serializing_if = "Option::is_none")]
        pub identity_provider: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub partners: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RelationshipsItemApplicationsItem {
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
    pub struct Answer200RelationshipsItem {
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
        pub mechanism: Option<String>,
        #[serde(rename = "mechanismLabel", default, skip_serializing_if = "Option::is_none")]
        pub mechanism_label: Option<String>,
        #[serde(rename = "mechanismKnown", default, skip_serializing_if = "Option::is_none")]
        pub mechanism_known: Option<bool>,
        #[serde(rename = "mechanismConfigured", default, skip_serializing_if = "Option::is_none")]
        pub mechanism_configured: Option<bool>,
        #[serde(rename = "brokersTo", default, skip_serializing_if = "Option::is_none")]
        pub brokers_to: Option<String>,
        #[serde(rename = "brokerUsable", default, skip_serializing_if = "Option::is_none")]
        pub broker_usable: Option<bool>,
        #[serde(rename = "brokerProblem", default, skip_serializing_if = "Option::is_none")]
        pub broker_problem: Option<String>,
        #[serde(rename = "brokeredUse", default, skip_serializing_if = "Option::is_none")]
        pub brokered_use: Option<sts_model_console_components_1::BrokeredUseValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub releases: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<Vec<Answer200RelationshipsItemApplicationsItem>>,
        #[serde(rename = "applicationCount", default, skip_serializing_if = "Option::is_none")]
        pub application_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributed: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unattributed: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NodesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationships: Option<Vec<String>>,
        /// This service's box: the trust realm's id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        /// This service's box: the trust realm's name.
        #[serde(rename = "realmName", default, skip_serializing_if = "Option::is_none")]
        pub realm_name: Option<String>,
        /// A foreign service provider's box: the application this service knows it
        /// as.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        /// A partner's box: its own name for itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EdgesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub to: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationship: Option<String>,
        #[serde(rename = "brokeredTo", default, skip_serializing_if = "Option::is_none")]
        pub brokered_to: Option<String>,
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        pub use_: Option<sts_model_console_components_1::BrokeredUseValue>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Drawing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub width: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub height: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failed: Option<Option<String>>,
        /// Whether this realm verifies what is presented (its mode), which one
        /// sentence of a picture's tooltips turns on. The console lays the picture
        /// out in the browser from the answer's data and reads it there (#444).
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RolesItem {
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
    pub struct Answer200ProtocolsItem {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200Realm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub empty: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filtered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationships: Option<Vec<Answer200RelationshipsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<Vec<Answer200NodesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub edges: Option<Vec<Answer200EdgesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_console_components_2::FederationBoxLinks>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<Answer200RolesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<Answer200ProtocolsItem>>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
    }
}

/// Set the language the console is drawn in, for yourself
pub mod set_console_language {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/console/language";
    pub const OPERATION_ID: &str = "setConsoleLanguage";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A BCP 47 tag a catalog answers, such as `fr-CA`, or empty to follow the
        /// browser.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lang: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_console_components_3::WithOkErrorsLocale;
}

/// The OpenAPI 3.1 document for the console's operations
pub mod get_console_open_api {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/openapi.json";
    pub const OPERATION_ID: &str = "getConsoleOpenApi";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200InfoLicense {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Info {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub license: Option<Answer200InfoLicense>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ServersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TagsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub openapi: String,
        pub info: Answer200Info,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub servers: Option<Vec<Answer200ServersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<Answer200TagsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub security: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
        pub paths: sts_model_console_components_2::InsideOpenApiDocumentPathsComponents,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub components: Option<sts_model_console_components_2::InsideOpenApiDocumentPathsComponents>,
    }
}

/// Every operation of both kinds, for the console's forms
pub mod get_console_operations {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/console/operations";
    pub const OPERATION_ID: &str = "getConsoleOperations";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OperationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(rename = "operationId", default, skip_serializing_if = "Option::is_none")]
        pub operation_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mirrors: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(rename = "drawnOn", default, skip_serializing_if = "Option::is_none")]
        pub drawn_on: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<Answer200OperationsItem>>,
    }
}

/// Fill the certificate form in from a profile
pub mod apply_pki_profile {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/console/pki/apply-profile";
    pub const OPERATION_ID: &str = "applyPkiProfile";

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

    pub type Answer200 = sts_model_console_components_3::WithOkErrorsWhy;
}

/// Generate the alternative (hybrid) key pair
pub mod generate_pki_alt_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/console/pki/generate-alt-keys";
    pub const OPERATION_ID: &str = "generatePkiAltKeyPair";

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

    pub type Answer200 = sts_model_console_components_3::WithOkErrorsWhy;
}

/// Generate a key pair into the form without issuing anything
pub mod generate_pki_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/console/pki/generate-keys";
    pub const OPERATION_ID: &str = "generatePkiKeyPair";

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

    pub type Answer200 = sts_model_console_components_3::WithOkErrorsWhy;
}

/// Load a stored object’s key pair back into the form
pub mod use_pki_stored_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/console/pki/use-key";
    pub const OPERATION_ID: &str = "usePkiStoredKey";

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

    pub type Answer200 = sts_model_console_components_3::WithOkErrorsWhy;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "generateClientSecret" => Some(serde_json::from_value::<generate_client_secret::Body>(value.clone()).map(|_| ())),
        "setConsoleLanguage" => Some(serde_json::from_value::<set_console_language::Body>(value.clone()).map(|_| ())),
        "applyPkiProfile" => Some(serde_json::from_value::<apply_pki_profile::Body>(value.clone()).map(|_| ())),
        "generatePkiAltKeyPair" => Some(serde_json::from_value::<generate_pki_alt_key_pair::Body>(value.clone()).map(|_| ())),
        "generatePkiKeyPair" => Some(serde_json::from_value::<generate_pki_key_pair::Body>(value.clone()).map(|_| ())),
        "usePkiStoredKey" => Some(serde_json::from_value::<use_pki_stored_key::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getConsoleShell", 200) => Some(serde_json::from_value::<get_console_shell::Answer200>(value.clone()).map(|_| ())),
        ("getApiExplorer", 200) => Some(serde_json::from_value::<get_api_explorer::Answer200>(value.clone()).map(|_| ())),
        ("generateClientSecret", 200) => Some(serde_json::from_value::<generate_client_secret::Answer200>(value.clone()).map(|_| ())),
        ("getConsoleNewApplicationForm", 200) => Some(serde_json::from_value::<get_console_new_application_form::Answer200>(value.clone()).map(|_| ())),
        ("getConsoleDashboard", 200) => Some(serde_json::from_value::<get_console_dashboard::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationSettings", 200) => Some(serde_json::from_value::<get_delegation_settings::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationAllowed", 200) => Some(serde_json::from_value::<get_delegation_allowed::Answer200>(value.clone()).map(|_| ())),
        ("getConsoleDelegationApplication", 200) => Some(serde_json::from_value::<get_console_delegation_application::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationChain", 200) => Some(serde_json::from_value::<get_delegation_chain::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationCluster", 200) => Some(serde_json::from_value::<get_delegation_cluster::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationMap", 200) => Some(serde_json::from_value::<get_delegation_map::Answer200>(value.clone()).map(|_| ())),
        ("getConsoleDelegationUser", 200) => Some(serde_json::from_value::<get_console_delegation_user::Answer200>(value.clone()).map(|_| ())),
        ("getFederationMap", 200) => Some(serde_json::from_value::<get_federation_map::Answer200>(value.clone()).map(|_| ())),
        ("setConsoleLanguage", 200) => Some(serde_json::from_value::<set_console_language::Answer200>(value.clone()).map(|_| ())),
        ("getConsoleOpenApi", 200) => Some(serde_json::from_value::<get_console_open_api::Answer200>(value.clone()).map(|_| ())),
        ("getConsoleOperations", 200) => Some(serde_json::from_value::<get_console_operations::Answer200>(value.clone()).map(|_| ())),
        ("applyPkiProfile", 200) => Some(serde_json::from_value::<apply_pki_profile::Answer200>(value.clone()).map(|_| ())),
        ("generatePkiAltKeyPair", 200) => Some(serde_json::from_value::<generate_pki_alt_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("generatePkiKeyPair", 200) => Some(serde_json::from_value::<generate_pki_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("usePkiStoredKey", 200) => Some(serde_json::from_value::<use_pki_stored_key::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
