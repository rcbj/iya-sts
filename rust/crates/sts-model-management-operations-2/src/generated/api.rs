// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// The SQL databases this realm reads people's attributes from (#94)
pub mod get_attribute_sources {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/attribute-sources";
    pub const OPERATION_ID: &str = "getAttributeSources";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "sourcesPage", default, skip_serializing_if = "Option::is_none")]
        pub sources_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SourcesItemStatus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cursor: Option<String>,
        #[serde(rename = "cursorKind", default, skip_serializing_if = "Option::is_none")]
        pub cursor_kind: Option<String>,
        #[serde(rename = "cursorOpen", default, skip_serializing_if = "Option::is_none")]
        pub cursor_open: Option<bool>,
        #[serde(rename = "cycleEndedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cycle_ended_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastRunAt", default, skip_serializing_if = "Option::is_none")]
        pub last_run_at: Option<String>,
        #[serde(rename = "lastRunPeople", default, skip_serializing_if = "Option::is_none")]
        pub last_run_people: Option<f64>,
        #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
        pub last_error: Option<String>,
        #[serde(rename = "lastCode", default, skip_serializing_if = "Option::is_none")]
        pub last_code: Option<String>,
        #[serde(rename = "lastErrorAt", default, skip_serializing_if = "Option::is_none")]
        pub last_error_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<f64>,
        #[serde(rename = "lastOkAt", default, skip_serializing_if = "Option::is_none")]
        pub last_ok_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SourcesItemTrustCertificatesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(rename = "notYetValid", default, skip_serializing_if = "Option::is_none")]
        pub not_yet_valid: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ca: Option<bool>,
        #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
        pub self_signed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sha256: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SourcesItemTrust {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<Vec<Answer200SourcesItemTrustCertificatesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<f64>,
        #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none")]
        pub ca_file: Option<String>,
        #[serde(rename = "publicRoots", default, skip_serializing_if = "Option::is_none")]
        pub public_roots: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SourcesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Answer200SourcesItemStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trust: Option<Answer200SourcesItemTrust>,
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
    pub struct Answer200Refused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub names: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prefixes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sources: Option<Vec<Answer200SourcesItem>>,
        #[serde(rename = "sourcesPaging", default, skip_serializing_if = "Option::is_none")]
        pub sources_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dialects: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub modes: Option<Vec<String>>,
        #[serde(rename = "onFailure", default, skip_serializing_if = "Option::is_none")]
        pub on_failure: Option<Vec<String>>,
        #[serde(rename = "passwordProviders", default, skip_serializing_if = "Option::is_none")]
        pub password_providers: Option<Vec<String>>,
        #[serde(rename = "hostPatterns", default, skip_serializing_if = "Option::is_none")]
        pub host_patterns: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<Answer200Refused>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue4>,
    }
}

/// Add an attribute source
pub mod add_attribute_source {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/attribute-sources/add-source";
    pub const OPERATION_ID: &str = "addAttributeSource";

    /// PostgreSQL, or MySQL / MariaDB.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDialect {
        #[serde(rename = "postgres")]
        Postgres,
        #[serde(rename = "mysql")]
        Mysql,
    }

    /// Where the password is read from, through common/secrets.js; never stored
    /// here.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPasswordProvider {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "file")]
        File,
        #[serde(rename = "aws")]
        Aws,
        #[serde(rename = "gcp")]
        Gcp,
        #[serde(rename = "azure")]
        Azure,
        #[serde(rename = "vault")]
        Vault,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRefreshItem {
        #[serde(rename = "once")]
        Once,
        #[serde(rename = "sign-in")]
        SignIn,
        #[serde(rename = "schedule")]
        Schedule,
        #[serde(rename = "on-demand")]
        OnDemand,
    }

    /// keep: the stored values stand and the sign-in proceeds; refuse: the sign-in
    /// is refused.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOnFailure {
        #[serde(rename = "keep")]
        Keep,
        #[serde(rename = "refuse")]
        Refuse,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The source's id in this realm.
        pub id: String,
        /// PostgreSQL, or MySQL / MariaDB.
        pub dialect: BodyDialect,
        /// The database host; attributeSources.hostPatterns may narrow it.
        pub host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        pub database: String,
        pub user: String,
        /// Where the password is read from, through common/secrets.js; never stored
        /// here.
        #[serde(rename = "passwordProvider", default, skip_serializing_if = "Option::is_none")]
        pub password_provider: Option<BodyPasswordProvider>,
        /// A path (file) or a secret's name; empty is the key-encryption key's
        /// location.
        #[serde(rename = "passwordRef", default, skip_serializing_if = "Option::is_none")]
        pub password_ref: Option<String>,
        /// The field, where the secret is a JSON object.
        #[serde(rename = "passwordField", default, skip_serializing_if = "Option::is_none")]
        pub password_field: Option<String>,
        /// A PEM file of CA certificates on this service's disk, added to
        /// caCertificates. TLS is always verified.
        #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none")]
        pub ca_file: Option<String>,
        /// The database's trust chain as PEM certificates, stored with the source.
        /// Trusted ALONE unless trustPublicRoots; with no chain and no caFile, the
        /// public roots are used. An empty string clears it. A block that does not
        /// parse, or an expired certificate, is refused.
        #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
        pub ca_certificates: Option<String>,
        /// Trust node's public roots beside caCertificates. Off by default.
        #[serde(rename = "trustPublicRoots", default, skip_serializing_if = "Option::is_none")]
        pub trust_public_roots: Option<bool>,
        /// The name the certificate is checked against; the host when empty.
        #[serde(rename = "serverName", default, skip_serializing_if = "Option::is_none")]
        pub server_name: Option<String>,
        /// A table or view, optionally schema.table.
        pub table: String,
        #[serde(rename = "keyColumn")]
        pub key_column: String,
        /// The person's attribute the key column holds (uid, employeeNumber,
        /// entryUUID…).
        #[serde(rename = "keyAttribute", default, skip_serializing_if = "Option::is_none")]
        pub key_attribute: Option<String>,
        /// { "<column>": "<directory attribute>" }. No attribute this service
        /// keeps, no identity or group membership, no mail; an attribute has one
        /// source.
        pub columns: serde_json::Map<String, serde_json::Value>,
        /// When a person is read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refresh: Option<Vec<BodyRefreshItem>>,
        /// The scheduled refresh's interval.
        #[serde(rename = "scheduleS", default, skip_serializing_if = "Option::is_none")]
        pub schedule_s: Option<i64>,
        #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<i64>,
        /// keep: the stored values stand and the sign-in proceeds; refuse: the
        /// sign-in is refused.
        #[serde(rename = "onFailure", default, skip_serializing_if = "Option::is_none")]
        pub on_failure: Option<BodyOnFailure>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors176;
}

/// Read one person from the sources now
pub mod refresh_attribute_source_person {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/attribute-sources/refresh-person";
    pub const OPERATION_ID: &str = "refreshAttributeSourcePerson";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub username: String,
        /// The source's id in this realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors176;
}

/// Read every person from a source now
pub mod refresh_attribute_source {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/attribute-sources/refresh-source";
    pub const OPERATION_ID: &str = "refreshAttributeSource";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The source's id in this realm.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors176;
}

/// Remove an attribute source
pub mod remove_attribute_source {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/attribute-sources/remove-source";
    pub const OPERATION_ID: &str = "removeAttributeSource";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The source's id in this realm.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors176;
}

/// Connect to a source and read one row, writing nothing
pub mod test_attribute_source {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/attribute-sources/test-source";
    pub const OPERATION_ID: &str = "testAttributeSource";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The source's id in this realm.
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors176;
}

/// Change an attribute source
pub mod update_attribute_source {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/attribute-sources/update-source";
    pub const OPERATION_ID: &str = "updateAttributeSource";

    /// PostgreSQL, or MySQL / MariaDB.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDialect {
        #[serde(rename = "postgres")]
        Postgres,
        #[serde(rename = "mysql")]
        Mysql,
    }

    /// Where the password is read from, through common/secrets.js; never stored
    /// here.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPasswordProvider {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "file")]
        File,
        #[serde(rename = "aws")]
        Aws,
        #[serde(rename = "gcp")]
        Gcp,
        #[serde(rename = "azure")]
        Azure,
        #[serde(rename = "vault")]
        Vault,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRefreshItem {
        #[serde(rename = "once")]
        Once,
        #[serde(rename = "sign-in")]
        SignIn,
        #[serde(rename = "schedule")]
        Schedule,
        #[serde(rename = "on-demand")]
        OnDemand,
    }

    /// keep: the stored values stand and the sign-in proceeds; refuse: the sign-in
    /// is refused.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOnFailure {
        #[serde(rename = "keep")]
        Keep,
        #[serde(rename = "refuse")]
        Refuse,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The source's id in this realm.
        pub id: String,
        /// PostgreSQL, or MySQL / MariaDB.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dialect: Option<BodyDialect>,
        /// The database host; attributeSources.hostPatterns may narrow it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// Where the password is read from, through common/secrets.js; never stored
        /// here.
        #[serde(rename = "passwordProvider", default, skip_serializing_if = "Option::is_none")]
        pub password_provider: Option<BodyPasswordProvider>,
        /// A path (file) or a secret's name; empty is the key-encryption key's
        /// location.
        #[serde(rename = "passwordRef", default, skip_serializing_if = "Option::is_none")]
        pub password_ref: Option<String>,
        /// The field, where the secret is a JSON object.
        #[serde(rename = "passwordField", default, skip_serializing_if = "Option::is_none")]
        pub password_field: Option<String>,
        /// A PEM file of CA certificates on this service's disk, added to
        /// caCertificates. TLS is always verified.
        #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none")]
        pub ca_file: Option<String>,
        /// The database's trust chain as PEM certificates, stored with the source.
        /// Trusted ALONE unless trustPublicRoots; with no chain and no caFile, the
        /// public roots are used. An empty string clears it. A block that does not
        /// parse, or an expired certificate, is refused.
        #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
        pub ca_certificates: Option<String>,
        /// Trust node's public roots beside caCertificates. Off by default.
        #[serde(rename = "trustPublicRoots", default, skip_serializing_if = "Option::is_none")]
        pub trust_public_roots: Option<bool>,
        /// The name the certificate is checked against; the host when empty.
        #[serde(rename = "serverName", default, skip_serializing_if = "Option::is_none")]
        pub server_name: Option<String>,
        /// A table or view, optionally schema.table.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub table: Option<String>,
        #[serde(rename = "keyColumn", default, skip_serializing_if = "Option::is_none")]
        pub key_column: Option<String>,
        /// The person's attribute the key column holds (uid, employeeNumber,
        /// entryUUID…).
        #[serde(rename = "keyAttribute", default, skip_serializing_if = "Option::is_none")]
        pub key_attribute: Option<String>,
        /// { "<column>": "<directory attribute>" }. No attribute this service
        /// keeps, no identity or group membership, no mail; an attribute has one
        /// source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub columns: Option<serde_json::Map<String, serde_json::Value>>,
        /// When a person is read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refresh: Option<Vec<BodyRefreshItem>>,
        /// The scheduled refresh's interval.
        #[serde(rename = "scheduleS", default, skip_serializing_if = "Option::is_none")]
        pub schedule_s: Option<i64>,
        #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<i64>,
        /// keep: the stored values stand and the sign-in proceeds; refuse: the
        /// sign-in is refused.
        #[serde(rename = "onFailure", default, skip_serializing_if = "Option::is_none")]
        pub on_failure: Option<BodyOnFailure>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors176;
}

/// The custom claims every new token and assertion will carry
pub mod get_claims {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/claims";
    pub const OPERATION_ID: &str = "getClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::ClaimSets;
}

/// Add one claim to one set
pub mod add_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/add";
    pub const OPERATION_ID: &str = "addClaim";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    /// The Kerberos PAC set only (#493): the PAC claim type. Defaults to string;
    /// ignored by the other sets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "string")]
        String,
        #[serde(rename = "int64")]
        Int64,
        #[serde(rename = "uint64")]
        Uint64,
        #[serde(rename = "boolean")]
        Boolean,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub name: String,
        /// May carry a ${...} placeholder.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// The Kerberos PAC set only (#493): the PAC claim type. Defaults to
        /// string; ignored by the other sets.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// The SAML 2.0 set only.
        #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
        pub name_format: Option<String>,
        /// The SAML 1.1 set only. Defaults to the WS-Federation claim namespace,
        /// which is what every relying party already reads.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Add one claim carrying a directory attribute
pub mod add_attribute_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/add-attribute-claim";
    pub const OPERATION_ID: &str = "addAttributeClaim";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    /// The JSON type of each value, in a JWT or UserInfo set. Ignored by the SAML
    /// sets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "string")]
        String,
        #[serde(rename = "number")]
        Number,
        #[serde(rename = "boolean")]
        Boolean,
        #[serde(rename = "json")]
        Json,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub name: String,
        /// The directory attribute.
        pub attribute: String,
        /// Every value rather than the first.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        /// The JSON type of each value, in a JWT or UserInfo set. Ignored by the
        /// SAML sets.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// The SAML 2.0 set only.
        #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
        pub name_format: Option<String>,
        /// The SAML 1.1 set only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Set which LDAP attributes one set carries
pub mod set_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/attributes";
    pub const OPERATION_ID: &str = "setClaimAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        /// LDAP attribute type names, from `attributeCatalogue`. An EMPTY array
        /// clears the selection — and so does an ABSENT one, so a misspelt field
        /// name empties the set rather than being refused. The reply names
        /// everything it `removed` and the audit log keeps a row saying the same,
        /// and `attributes-clear` is how a caller that means it says so.
        pub attributes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Put every catalogued attribute in one set
pub mod select_all_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/attributes-all";
    pub const OPERATION_ID: &str = "selectAllClaimAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Take every directory attribute out of one set
pub mod clear_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/attributes-clear";
    pub const OPERATION_ID: &str = "clearClaimAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Empty one set
pub mod clear_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/clear";
    pub const OPERATION_ID: &str = "clearClaims";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Remove one claim from one set
pub mod remove_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/remove";
    pub const OPERATION_ID: &str = "removeClaim";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Set a whole claim set at once
pub mod replace_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claims/replace";
    pub const OPERATION_ID: &str = "replaceClaims";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub claims: Vec<sts_model_management_components_1::ClaimEntry>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// What people agreed applications may ask for on their behalf
pub mod get_consent {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/consent";
    pub const OPERATION_ID: &str = "getConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(rename = "globalsPage", default, skip_serializing_if = "Option::is_none")]
        pub globals_page: Option<i64>,
        #[serde(rename = "usersPage", default, skip_serializing_if = "Option::is_none")]
        pub users_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GlobalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none")]
        pub client_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permission: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub granted: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UsersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub raw: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub globals: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consents: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<i64>,
        #[serde(rename = "countsOf", default, skip_serializing_if = "Option::is_none")]
        pub counts_of: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Search {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exact: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scanned: Option<i64>,
        #[serde(rename = "scanLimit", default, skip_serializing_if = "Option::is_none")]
        pub scan_limit: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holders: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub complete: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicationChoicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub storable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(rename = "globalAttribute", default, skip_serializing_if = "Option::is_none")]
        pub global_attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub globals: Option<Vec<Answer200GlobalsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<Vec<Answer200UsersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub windowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub search: Option<Answer200Search>,
        #[serde(rename = "globalsPaging", default, skip_serializing_if = "Option::is_none")]
        pub globals_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(rename = "usersPaging", default, skip_serializing_if = "Option::is_none")]
        pub users_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<Answer200Query>,
        #[serde(rename = "withdrawnAttribute", default, skip_serializing_if = "Option::is_none")]
        pub withdrawn_attribute: Option<String>,
        #[serde(rename = "applicationChoices", default, skip_serializing_if = "Option::is_none")]
        pub application_choices: Option<Vec<Answer200ApplicationChoicesItem>>,
    }
}

/// Forget everything one person agreed to
pub mod forget_user_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/consent/forget-user-consent";
    pub const OPERATION_ID: &str = "forgetUserConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person whose answers are forgotten.
        pub username: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors152;
}

/// Consent a scope for everybody who signs in to an application
pub mod grant_global_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/consent/grant-global-consent";
    pub const OPERATION_ID: &str = "grantGlobalConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application people sign in to, by its identifier exactly as
        /// `ou=applications` holds it. This is the CLIENT — the party that will
        /// name the scope in a request — and not the resource that exposes it.
        pub client: String,
        /// The scope, exactly as a client puts it in a `scope` parameter. A
        /// delegated permission is its WHOLE identifier.
        pub scope: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors152;
}

/// Withdraw everything one person agreed to for one application
pub mod revoke_application_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/consent/revoke-application-consent";
    pub const OPERATION_ID: &str = "revokeApplicationConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, exactly as /admin/users names them.
        pub username: String,
        /// The application whose every consent is withdrawn.
        pub client: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors152;
}

/// Take back one answer one person gave
pub mod revoke_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/consent/revoke-consent";
    pub const OPERATION_ID: &str = "revokeConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, exactly as /admin/users names them. It is normalised the
        /// same way every identity here is, so `alice` and her urn:uuid: subject
        /// are one person.
        pub username: String,
        /// The application they consented it to.
        pub client: String,
        /// The scope they consented.
        pub scope: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors152;
}

/// Stop consenting a scope for everybody
pub mod revoke_global_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/consent/revoke-global-consent";
    pub const OPERATION_ID: &str = "revokeGlobalConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application holding it.
        pub client: String,
        /// The scope to stop consenting.
        pub scope: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors152;
}

/// Which claims an issued Verifiable Credential carries
pub mod get_credential_claims {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/credential-claims";
    pub const OPERATION_ID: &str = "getCredentialClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200AttributesItemExampleValue {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributesItemExample {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<Answer200AttributesItemExampleValue>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributesItem {
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
        pub example: Option<Answer200AttributesItemExample>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200PreviewClaimsReportItemValue {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreviewClaimsReportItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ldap: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<Answer200PreviewClaimsReportItemValue>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ldp_term: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreviewClaims {
        /// The credential subject's claims.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub report: Option<Vec<Answer200PreviewClaimsReportItem>>,
        #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
        pub entry_found: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Preview {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Answer200PreviewClaims>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selected: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<Vec<String>>,
        #[serde(rename = "ldpOmitted", default, skip_serializing_if = "Option::is_none")]
        pub ldp_omitted: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<Answer200AttributesItem>>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preview: Option<Answer200Preview>,
    }
}

/// Add one attribute to the credential claim set
pub mod add_credential_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/credential-claims/add";
    pub const OPERATION_ID: &str = "addCredentialClaim";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        /// An alias for `attribute`; `vcAction()` reads `body.attribute ||
        /// body.name`, so both spellings have always worked and only one was
        /// published.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors75;
}

/// Back to the default selection
pub mod reset_credential_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/credential-claims/defaults";
    pub const OPERATION_ID: &str = "resetCredentialClaims";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors75;
}

/// Sweep the directory without changing the selection
pub mod populate_directory {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/credential-claims/populate";
    pub const OPERATION_ID: &str = "populateDirectory";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors75;
}

/// Remove one attribute from the credential claim set
pub mod remove_credential_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/credential-claims/remove";
    pub const OPERATION_ID: &str = "removeCredentialClaim";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        /// An alias for `attribute`; `vcAction()` reads `body.attribute ||
        /// body.name`, so both spellings have always worked and only one was
        /// published.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors75;
}

/// Set the whole credential claim set
pub mod select_credential_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/credential-claims/select";
    pub const OPERATION_ID: &str = "selectCredentialClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// LDAP attribute type names, from the catalogue.
        pub attributes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors75;
}

/// Who acted on whose behalf, through what, to reach what
pub mod get_delegation {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/delegation";
    pub const OPERATION_ID: &str = "getDelegation";

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

    pub type Answer200 = sts_model_management_components_2::DelegationList;
}

/// Everything delegated through one application or to it
pub mod get_delegation_application {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/delegation/application";
    pub const OPERATION_ID: &str = "getDelegationApplication";

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
    pub struct Answer200ApplicationRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<f64>,
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
    pub struct Answer200ApplicationsItemRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<f64>,
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<Answer200Application>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub asked: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub key: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub registered: Option<bool>,
        #[serde(rename = "registeredName", default, skip_serializing_if = "Option::is_none")]
        pub registered_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<sts_model_management_components_4::WithIdKindKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_management_components_4::WithRealmIssuerNodes2>,
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
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_management_components_4::WithKeyNamesLabel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chooser: Option<sts_model_management_components_4::WithTotalEntriesSlice>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_management_components_4::WithUsersAppsName>,
    }
}

/// Who may act for whom at WS-Trust and the token exchange
pub mod get_delegation_policy {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/delegation/policy";
    pub const OPERATION_ID: &str = "getDelegationPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "policyPairsPage", default, skip_serializing_if = "Option::is_none")]
        pub policy_pairs_page: Option<i64>,
        #[serde(rename = "intermediariesPage", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_page: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PairsItem {
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
    pub struct Answer200IntermediariesItem {
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
    pub struct Answer200PeopleItem {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "protectedGroups", default, skip_serializing_if = "Option::is_none")]
        pub protected_groups: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pairs: Option<Vec<Answer200PairsItem>>,
        #[serde(rename = "pairsPaging", default, skip_serializing_if = "Option::is_none")]
        pub pairs_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediaries: Option<Vec<Answer200IntermediariesItem>>,
        #[serde(rename = "intermediariesPaging", default, skip_serializing_if = "Option::is_none")]
        pub intermediaries_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<Vec<Answer200PeopleItem>>,
        #[serde(rename = "peoplePaging", default, skip_serializing_if = "Option::is_none")]
        pub people_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
    }
}

/// Everything issued and delegated in one person's name
pub mod get_delegation_user {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/delegation/user";
    pub const OPERATION_ID: &str = "getDelegationUser";

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
        pub initial: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200User {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presented: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forms: Option<Vec<Option<String>>>,
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
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<f64>>,
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
        pub unknown: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
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
        pub initial: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UsersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presented: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forms: Option<Vec<Option<String>>>,
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
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<f64>>,
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<Answer200User>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub asked: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub key: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<sts_model_management_components_4::WithSeqOriginAt2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flows: Option<Vec<Answer200FlowsItem>>,
        #[serde(rename = "onDelegationLines", default, skip_serializing_if = "Option::is_none")]
        pub on_delegation_lines: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<sts_model_management_components_4::WithIdKindKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_management_components_4::WithRealmIssuerNodes2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<Vec<Answer200UsersItem>>,
        #[serde(rename = "usersComplete", default, skip_serializing_if = "Option::is_none")]
        pub users_complete: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<sts_model_management_components_4::WithKeyNamesLabel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chooser: Option<sts_model_management_components_4::WithTotalEntriesSlice>,
        #[serde(rename = "mapKey", default, skip_serializing_if = "Option::is_none")]
        pub map_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<sts_model_management_components_4::WithUsersAppsName>,
    }
}

/// Report device compliance (an MDM or posture feed)
pub mod report_device_compliance {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/device-compliance";
    pub const OPERATION_ID: &str = "reportDeviceCompliance";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyKind {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "webauthn")]
        Webauthn,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyStatus {
        #[serde(rename = "compliant")]
        Compliant,
        #[serde(rename = "not-compliant")]
        NotCompliant,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReportsItemKeyKind {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "webauthn")]
        Webauthn,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReportsItemStatus {
        #[serde(rename = "compliant")]
        Compliant,
        #[serde(rename = "not-compliant")]
        NotCompliant,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyReportsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none")]
        pub key_kind: Option<BodyReportsItemKeyKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<BodyReportsItemStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none")]
        pub key_kind: Option<BodyKeyKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<BodyStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reports: Option<Vec<BodyReportsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors12;
}

/// How a device is registered and recognised here
pub mod get_device_registration {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/device-registration";
    pub const OPERATION_ID: &str = "getDeviceRegistration";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolmentItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RecognitionItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MdmFeed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(rename = "maxReports", default, skip_serializing_if = "Option::is_none")]
        pub max_reports: Option<f64>,
        #[serde(rename = "identifiedBy", default, skip_serializing_if = "Option::is_none")]
        pub identified_by: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ReceivedCaep {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Signals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub caep: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub risc: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RecordedAt {
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Decisions {
        #[serde(rename = "riskSignals", default, skip_serializing_if = "Option::is_none")]
        pub risk_signals: Option<Vec<String>>,
        #[serde(rename = "expectRegistered", default, skip_serializing_if = "Option::is_none")]
        pub expect_registered: Option<bool>,
        #[serde(rename = "refuseCompromised", default, skip_serializing_if = "Option::is_none")]
        pub refuse_compromised: Option<bool>,
        #[serde(rename = "requireCompliantDevice", default, skip_serializing_if = "Option::is_none")]
        pub require_compliant_device: Option<bool>,
        #[serde(rename = "compliantDeviceAttested", default, skip_serializing_if = "Option::is_none")]
        pub compliant_device_attested: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UnattestedKeys {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accepted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub predicate: Option<String>,
        #[serde(rename = "adminKeys", default, skip_serializing_if = "Option::is_none")]
        pub admin_keys: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FreshKeyAttestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub predicate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nonce: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TrustAnchorsItemShippedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub used: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TrustAnchorsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub count: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shipped: Option<Vec<Answer200TrustAnchorsItemShippedItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Challenges {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<String>,
        #[serde(rename = "perRealm", default, skip_serializing_if = "Option::is_none")]
        pub per_realm: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persisted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub live: Option<i64>,
        #[serde(rename = "ttlSeconds", default, skip_serializing_if = "Option::is_none")]
        pub ttl_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purposes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AndroidStatus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<String>,
        #[serde(rename = "loadedAt", default, skip_serializing_if = "Option::is_none")]
        pub loaded_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stale: Option<bool>,
        #[serde(rename = "staleAfterHours", default, skip_serializing_if = "Option::is_none")]
        pub stale_after_hours: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<Vec<Answer200EnrolmentItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recognition: Option<Vec<Answer200RecognitionItem>>,
        #[serde(rename = "ownerKinds", default, skip_serializing_if = "Option::is_none")]
        pub owner_kinds: Option<Vec<String>>,
        #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
        pub key_kinds: Option<Vec<String>>,
        #[serde(rename = "keyProofs", default, skip_serializing_if = "Option::is_none")]
        pub key_proofs: Option<Vec<String>>,
        #[serde(rename = "attestationLevels", default, skip_serializing_if = "Option::is_none")]
        pub attestation_levels: Option<Vec<String>>,
        #[serde(rename = "attestationFormats", default, skip_serializing_if = "Option::is_none")]
        pub attestation_formats: Option<Vec<String>>,
        #[serde(rename = "complianceStates", default, skip_serializing_if = "Option::is_none")]
        pub compliance_states: Option<Vec<String>>,
        #[serde(rename = "complianceSources", default, skip_serializing_if = "Option::is_none")]
        pub compliance_sources: Option<Vec<String>>,
        #[serde(rename = "mdmFeed", default, skip_serializing_if = "Option::is_none")]
        pub mdm_feed: Option<Answer200MdmFeed>,
        #[serde(rename = "receivedCaep", default, skip_serializing_if = "Option::is_none")]
        pub received_caep: Option<Answer200ReceivedCaep>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Answer200Signals>,
        #[serde(rename = "recordedAt", default, skip_serializing_if = "Option::is_none")]
        pub recorded_at: Option<Answer200RecordedAt>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decisions: Option<Answer200Decisions>,
        #[serde(rename = "unattestedKeys", default, skip_serializing_if = "Option::is_none")]
        pub unattested_keys: Option<Answer200UnattestedKeys>,
        #[serde(rename = "freshKeyAttestation", default, skip_serializing_if = "Option::is_none")]
        pub fresh_key_attestation: Option<Answer200FreshKeyAttestation>,
        #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchors: Option<Vec<Answer200TrustAnchorsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenges: Option<Answer200Challenges>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
        #[serde(rename = "androidStatus", default, skip_serializing_if = "Option::is_none")]
        pub android_status: Option<Answer200AndroidStatus>,
    }
}

/// Every device in this realm, paged and filtered, or one
pub mod get_devices {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/devices";
    pub const OPERATION_ID: &str = "getDevices";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOwnerKind {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryCompliance {
        #[serde(rename = "compliant")]
        Compliant,
        #[serde(rename = "not-compliant")]
        NotCompliant,
        #[serde(rename = "unknown")]
        Unknown,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryAttestation {
        #[serde(rename = "attested")]
        Attested,
        #[serde(rename = "self-asserted")]
        SelfAsserted,
        #[serde(rename = "bearer")]
        Bearer,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryKeyKind {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "webauthn")]
        Webauthn,
        #[serde(rename = "native-sso")]
        NativeSso,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryStatus {
        #[serde(rename = "active")]
        Active,
        #[serde(rename = "compromised")]
        Compromised,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
        pub owner_kind: Option<QueryOwnerKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<QueryCompliance>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<QueryAttestation>,
        #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none")]
        pub key_kind: Option<QueryKeyKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<QueryStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceAttestation {
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
    pub struct Answer200DeviceComplianceChange {
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
    pub struct Answer200DeviceStatusChange {
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
    pub struct Answer200DeviceEnrolment {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceRememberedBrowser {
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
    pub struct Answer200Device {
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
        pub keys: Option<sts_model_management_components_2::WithAdditionalPropertiesPropertiesLevel>,
        #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
        pub key_kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<Answer200DeviceAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<String>,
        #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
        pub compliance_change: Option<Answer200DeviceComplianceChange>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
        pub status_change: Option<Answer200DeviceStatusChange>,
        #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
        pub risk_level: Option<String>,
        #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
        pub risk_change: Option<sts_model_management_components_2::RiskChangeValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<Answer200DeviceEnrolment>,
        #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
        pub native_sso: Option<bool>,
        #[serde(rename = "rememberedBrowser", default, skip_serializing_if = "Option::is_none")]
        pub remembered_browser: Option<Answer200DeviceRememberedBrowser>,
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
    pub struct Answer200Vocabulary {
        #[serde(rename = "ownerKinds", default, skip_serializing_if = "Option::is_none")]
        pub owner_kinds: Option<Vec<String>>,
        #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
        pub key_kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub statuses: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platforms: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<Answer200Device>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vocabulary: Option<Answer200Vocabulary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        /// What the list was narrowed by.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub devices: Option<Vec<sts_model_management_components_2::DeviceView>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(rename = "devicesPaging", default, skip_serializing_if = "Option::is_none")]
        pub devices_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
    }
}

/// Add a key a device is recognised by
pub mod add_device_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/add-key";
    pub const OPERATION_ID: &str = "addDeviceKey";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "webauthn")]
        Webauthn,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The device id.
        pub id: String,
        pub kind: BodyKind,
        /// PEM, JWK (object or JSON) or credential id.
        pub value: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// Register a device, owned by a person or an application
pub mod create_device {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/create";
    pub const OPERATION_ID: &str = "createDevice";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOwnerKind {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeysItemKind {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "webauthn")]
        Webauthn,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKeysItemKind>,
        /// PEM, JWK (object or JSON) or credential id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyKind {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "webauthn")]
        Webauthn,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A username, an application identifier or a DN.
        pub owner: String,
        #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
        pub owner_kind: Option<BodyOwnerKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// ios, ipados, android, macos, windows, linux, chromeos, other or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
        /// Client ids or application identifiers: an array, or one string, comma
        /// separated.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<BodyKeysItem>>,
        #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none")]
        pub key_kind: Option<BodyKeyKind>,
        /// One key, with keyKind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<serde_json::Value>,
        #[serde(rename = "keyLabel", default, skip_serializing_if = "Option::is_none")]
        pub key_label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// The device register counted, and its events day by day
pub mod get_devices_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/devices/monitor";
    pub const OPERATION_ID: &str = "getDevicesMonitor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CountsNativeSso {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub live: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ended: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub none: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(rename = "byOwnerKind", default, skip_serializing_if = "Option::is_none")]
        pub by_owner_kind: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byCompliance", default, skip_serializing_if = "Option::is_none")]
        pub by_compliance: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byAttestation", default, skip_serializing_if = "Option::is_none")]
        pub by_attestation: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byKeyKind", default, skip_serializing_if = "Option::is_none")]
        pub by_key_kind: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byEnrolment", default, skip_serializing_if = "Option::is_none")]
        pub by_enrolment: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
        pub by_status: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byRiskLevel", default, skip_serializing_if = "Option::is_none")]
        pub by_risk_level: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byKeyAttestationFormat", default, skip_serializing_if = "Option::is_none")]
        pub by_key_attestation_format: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<f64>,
        #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
        pub native_sso: Option<Answer200CountsNativeSso>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub windowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counted: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub complete: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TimelineRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub day: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evicted: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TimelineTotals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evicted: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Timeline {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200TimelineRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200TimelineTotals>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Activity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recognitions: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolments: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "attestationLevels", default, skip_serializing_if = "Option::is_none")]
        pub attestation_levels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "attestationFormats", default, skip_serializing_if = "Option::is_none")]
        pub attestation_formats: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "attestationRefusals", default, skip_serializing_if = "Option::is_none")]
        pub attestation_refusals: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeline: Option<Answer200Timeline>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub activity: Option<Answer200Activity>,
        #[serde(rename = "complianceSources", default, skip_serializing_if = "Option::is_none")]
        pub compliance_sources: Option<Vec<String>>,
    }
}

/// Remove a device
pub mod remove_device {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/remove";
    pub const OPERATION_ID: &str = "removeDevice";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The device id.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// Remove one of a device's keys
pub mod remove_device_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/remove-key";
    pub const OPERATION_ID: &str = "removeDeviceKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The device id.
        pub id: String,
        /// The key id or thumbprint.
        pub key: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// Set a device's compliance, as an administrator
pub mod set_device_compliance {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/set-compliance";
    pub const OPERATION_ID: &str = "setDeviceCompliance";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyStatus {
        #[serde(rename = "compliant")]
        Compliant,
        #[serde(rename = "not-compliant")]
        NotCompliant,
        #[serde(rename = "unknown")]
        Unknown,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The device id.
        pub id: String,
        pub status: BodyStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// Mark a device compromised, or restore it
pub mod set_device_status {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/set-status";
    pub const OPERATION_ID: &str = "setDeviceStatus";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyStatus {
        #[serde(rename = "active")]
        Active,
        #[serde(rename = "compromised")]
        Compromised,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The device id.
        pub id: String,
        pub status: BodyStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// Change a device's label, owner or description
pub mod update_device {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/devices/update";
    pub const OPERATION_ID: &str = "updateDevice";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOwnerKind {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The device id.
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
        pub owner_kind: Option<BodyOwnerKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
        /// The whole list, as on create.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors10;
}

/// The EST server: endpoints, Issuing CA, profiles, host names, enrolled
/// certificates, settings
pub mod get_est {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/est";
    pub const OPERATION_ID: &str = "getEst";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "certificatesPage", default, skip_serializing_if = "Option::is_none")]
        pub certificates_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EndpointsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub section: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(rename = "labelFormUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label_form_url: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LabelForm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200HierarchyAuthority {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
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
    pub struct Answer200Hierarchy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authority: Option<Answer200HierarchyAuthority>,
        #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
        pub chain_pem: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticationCredentialsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(rename = "managedAt", default, skip_serializing_if = "Option::is_none")]
        pub managed_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authentication {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub basic: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<bool>,
        #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
        pub server_key_generation: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<Vec<Answer200AuthenticationCredentialsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub needs: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
        pub is_default: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub urls: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RefusedProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CsrAttributesSignatureAlgorithmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub oid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CsrAttributes {
        #[serde(rename = "signatureAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub signature_algorithms: Option<Vec<Answer200CsrAttributesSignatureAlgorithmsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Mode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub development: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub product: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specifications: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Vec<Answer200EndpointsItem>>,
        #[serde(rename = "labelForm", default, skip_serializing_if = "Option::is_none")]
        pub label_form: Option<Answer200LabelForm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hierarchy: Option<Answer200Hierarchy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication: Option<Answer200Authentication>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ProfilesItem>>,
        #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default_profile: Option<Option<String>>,
        #[serde(rename = "refusedProfiles", default, skip_serializing_if = "Option::is_none")]
        pub refused_profiles: Option<Vec<Answer200RefusedProfilesItem>>,
        #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
        pub host_names: Option<sts_model_management_components_4::WithAtOperationOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<sts_model_management_components_4::WithPagingRowsEntry2>,
        #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithms: Option<Vec<String>>,
        #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
        pub revocation_reasons: Option<Vec<String>>,
        #[serde(rename = "csrAttributes", default, skip_serializing_if = "Option::is_none")]
        pub csr_attributes: Option<Answer200CsrAttributes>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<Answer200Mode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub monitor: Option<String>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Register a certificate host name on an entry
pub mod add_est_host_name {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/est/add-host-name";
    pub const OPERATION_ID: &str = "addEstHostName";

    /// Whether `identifier` names a person (a username) or an application (its
    /// identifier).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Whether `identifier` names a person (a username) or an application (its
        /// identifier).
        pub kind: BodyKind,
        /// The username or application identifier.
        pub identifier: String,
        /// A DNS name or an IP address.
        #[serde(rename = "hostName")]
        pub host_name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors164;
}

/// Issue a certificate with a key pair this service generates
pub mod issue_est_server_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/est/issue-server-key";
    pub const OPERATION_ID: &str = "issueEstServerKey";

    /// Whether `identifier` names a person (a username) or an application (its
    /// identifier).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "application")]
        Application,
    }

    /// One of the nine profiles; `est.defaultProfile` when omitted.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProfile {
        #[serde(rename = "tls-server")]
        TlsServer,
        #[serde(rename = "tls-client")]
        TlsClient,
        #[serde(rename = "tls-server-client")]
        TlsServerClient,
        #[serde(rename = "digital-signature")]
        DigitalSignature,
        #[serde(rename = "key-encipherment")]
        KeyEncipherment,
        #[serde(rename = "code-signing")]
        CodeSigning,
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "timestamping")]
        Timestamping,
        #[serde(rename = "smartcard-logon")]
        SmartcardLogon,
    }

    /// A key algorithm id from GET /admin-api/est `keyAlgorithms`; ec-p256 when
    /// omitted.
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
        /// Whether `identifier` names a person (a username) or an application (its
        /// identifier).
        pub kind: BodyKind,
        /// The username or application identifier.
        pub identifier: String,
        /// One of the nine profiles; `est.defaultProfile` when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<BodyProfile>,
        /// A key algorithm id from GET /admin-api/est `keyAlgorithms`; ec-p256 when
        /// omitted.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors162;
}

/// What the EST server has done: requests, issuances, refusals
pub mod get_est_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/est/monitor";
    pub const OPERATION_ID: &str = "getEstMonitor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Totals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requests: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Certificates {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OperationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PrincipalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ErrorCodesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StatusesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub since: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<Answer200Certificates>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<Answer200OperationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ProfilesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principals: Option<Vec<Answer200PrincipalsItem>>,
        #[serde(rename = "errorCodes", default, skip_serializing_if = "Option::is_none")]
        pub error_codes: Option<Vec<Answer200ErrorCodesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub statuses: Option<Vec<Answer200StatusesItem>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recent: Option<sts_model_management_components_4::WithOkMessageErrors157>,
    }
}

/// Remove a certificate host name from an entry
pub mod remove_est_host_name {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/est/remove-host-name";
    pub const OPERATION_ID: &str = "removeEstHostName";

    /// Whether `identifier` names a person (a username) or an application (its
    /// identifier).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Whether `identifier` names a person (a username) or an application (its
        /// identifier).
        pub kind: BodyKind,
        /// The username or application identifier.
        pub identifier: String,
        /// The name to remove.
        #[serde(rename = "hostName")]
        pub host_name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors164;
}

/// Revoke a certificate enrolled over EST
pub mod revoke_est_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/est/revoke-certificate";
    pub const OPERATION_ID: &str = "revokeEstCertificate";

    /// The RFC 5280 section 5.3.1 reason; unspecified when omitted.
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
        /// The serial, from GET /admin-api/est.
        pub serial: String,
        /// The RFC 5280 section 5.3.1 reason; unspecified when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors163;
}

/// Which applications may reach which, decided in advance
pub mod get_permissions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/permissions";
    pub const OPERATION_ID: &str = "getPermissions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ResourcesItemPermissionsItemGrantedToItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ResourcesItemPermissionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub description: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub raw: Option<Option<String>>,
        #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
        pub granted_to: Option<Vec<Answer200ResourcesItemPermissionsItemGrantedToItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ResourcesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub base_uri: Option<Option<String>>,
        #[serde(rename = "rawBaseUri", default, skip_serializing_if = "Option::is_none")]
        pub raw_base_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<Answer200ResourcesItemPermissionsItem>>,
        #[serde(rename = "grantsHeld", default, skip_serializing_if = "Option::is_none")]
        pub grants_held: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<Vec<Answer200ResourcesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<sts_model_management_components_4::WithClientClientNamePermissionId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_management_components_4::WithApplicationsGrantsLines>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_management_components_4::WithRealmIssuerNodes2>,
    }
}

/// Expose one permission on an application
pub mod define_permission {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/permissions/define-permission";
    pub const OPERATION_ID: &str = "definePermission";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application that exposes it.
        pub resource: String,
        /// The permission name — the word a client will send inside a `scope`.
        pub name: String,
        /// Optional prose, shown wherever the permission is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors136;
}

/// Grant a client application a permission on another one
pub mod grant_permission {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/permissions/grant-permission";
    pub const OPERATION_ID: &str = "grantPermission";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application that WILL ASK — the one whose `client_id` appears on the
        /// token request. Not the one exposing the API.
        pub client: String,
        /// The whole permission identifier, base URI and name together.
        pub permission: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors136;
}

/// Which applications are joined to each other by delegated permissions
pub mod get_permission_groups {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/permissions/groups";
    pub const OPERATION_ID: &str = "getPermissionGroups";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(rename = "groupsPage", default, skip_serializing_if = "Option::is_none")]
        pub groups_page: Option<i64>,
        #[serde(rename = "groupGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_grants_page: Option<i64>,
        #[serde(rename = "groupPermissionsPage", default, skip_serializing_if = "Option::is_none")]
        pub group_permissions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
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
    pub struct Answer200GroupsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<sts_model_management_components_4::WithApplicationsGrantsLines2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Group {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<sts_model_management_components_4::WithApplicationsGrantsLines2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub application: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<Answer200GroupsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<Answer200Group>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_management_components_4::WithApplicationsGrantsLines>,
        #[serde(rename = "grantsPaging", default, skip_serializing_if = "Option::is_none")]
        pub grants_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<sts_model_management_components_4::WithClientClientNamePermissionId>,
        #[serde(rename = "permissionsPaging", default, skip_serializing_if = "Option::is_none")]
        pub permissions_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<sts_model_management_components_4::WithRealmIssuerNodes2>,
    }
}

/// Stop exposing a permission
pub mod remove_permission {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/permissions/remove-permission";
    pub const OPERATION_ID: &str = "removePermission";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application that exposes it.
        pub resource: String,
        /// The permission name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors136;
}

/// Take a permission away from a client application
pub mod revoke_permission {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/permissions/revoke-permission";
    pub const OPERATION_ID: &str = "revokePermission";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application holding it.
        pub client: String,
        /// The whole permission identifier.
        pub permission: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors136;
}

/// Give an application the base URI its permissions hang off
pub mod set_permission_base {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/permissions/set-permission-base";
    pub const OPERATION_ID: &str = "setPermissionBase";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application that EXPOSES the API, by its identifier exactly as
        /// `ou=applications` holds it.
        pub resource: String,
        /// An absolute URI. Empty clears it.
        #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
        pub base_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors136;
}

/// Started post-login activities in this realm (#1111)
pub mod get_post_login_activities {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/post-login-activities";
    pub const OPERATION_ID: &str = "getPostLoginActivities";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groupq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groupfrom: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LimitsIntervalDays {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub min: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dflt: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LimitsMaxMails {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub min: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dflt: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LimitsPerRun {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub min: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dflt: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LimitsGroups {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Limits {
        #[serde(rename = "intervalDays", default, skip_serializing_if = "Option::is_none")]
        pub interval_days: Option<Answer200LimitsIntervalDays>,
        #[serde(rename = "maxMails", default, skip_serializing_if = "Option::is_none")]
        pub max_mails: Option<Answer200LimitsMaxMails>,
        #[serde(rename = "perRun", default, skip_serializing_if = "Option::is_none")]
        pub per_run: Option<Answer200LimitsPerRun>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Answer200LimitsGroups>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupChooserChosenItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cn: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dn: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupChooserPaneShownItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cn: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupChooserPane {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<Vec<Answer200GroupChooserPaneShownItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupChooser {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub search: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chosen: Option<Vec<Answer200GroupChooserChosenItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pane: Option<Answer200GroupChooserPane>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StartedItemRun {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cursor: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub read: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mailed: Option<f64>,
        #[serde(rename = "notDue", default, skip_serializing_if = "Option::is_none")]
        pub not_due: Option<f64>,
        #[serde(rename = "heldBack", default, skip_serializing_if = "Option::is_none")]
        pub held_back: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<f64>,
        #[serde(rename = "lastRunAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_run_at: Option<Option<String>>,
        #[serde(rename = "lastSummary", default, skip_serializing_if = "Option::is_none")]
        pub last_summary: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StartedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub run: Option<Answer200StartedItemRun>,
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<String>,
        #[serde(rename = "everyMinutes", default, skip_serializing_if = "Option::is_none")]
        pub every_minutes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub activities: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<Answer200Limits>,
        #[serde(rename = "mailAvailable", default, skip_serializing_if = "Option::is_none")]
        pub mail_available: Option<bool>,
        #[serde(rename = "activityEnabled", default, skip_serializing_if = "Option::is_none")]
        pub activity_enabled: Option<bool>,
        #[serde(rename = "groupChooser", default, skip_serializing_if = "Option::is_none")]
        pub group_chooser: Option<Answer200GroupChooser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub started: Option<Vec<Answer200StartedItem>>,
    }
}

/// End a started post-login activity
pub mod end_post_login_activity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/post-login-activities/end";
    pub const OPERATION_ID: &str = "endPostLoginActivity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The started activity.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors187;
}

/// Pause a started post-login activity
pub mod pause_post_login_activity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/post-login-activities/pause";
    pub const OPERATION_ID: &str = "pausePostLoginActivity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The started activity.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors187;
}

/// Resume a paused post-login activity
pub mod resume_post_login_activity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/post-login-activities/resume";
    pub const OPERATION_ID: &str = "resumePostLoginActivity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The started activity.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors187;
}

/// Start a post-login activity
pub mod start_post_login_activity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/post-login-activities/start";
    pub const OPERATION_ID: &str = "startPostLoginActivity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The post-login activity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub activity: Option<String>,
        /// Groups' cns or DNs, the people being the union of their members; empty
        /// or absent for everybody in the realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
        /// Days between two mails to one person (default 7).
        #[serde(rename = "intervalDays", default, skip_serializing_if = "Option::is_none")]
        pub interval_days: Option<i64>,
        /// The most mails one person is sent (default 3).
        #[serde(rename = "maxMails", default, skip_serializing_if = "Option::is_none")]
        pub max_mails: Option<i64>,
        /// People read per run of the job (default 1000).
        #[serde(rename = "perRun", default, skip_serializing_if = "Option::is_none")]
        pub per_run: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors187;
}

/// The custom attributes every new SAML assertion will carry
pub mod get_saml_attributes {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/saml-attributes";
    pub const OPERATION_ID: &str = "getSamlAttributes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SetsItemAttributeClaimPreviewItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub carried: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<sts_model_management_components_1::ClaimValueWouldIssued>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SetsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<sts_model_management_components_4::WithOkMessageErrors73>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        /// The claims one person would be issued, keyed and nested by the claim
        /// names the catalogue and an administrator chose.
        #[serde(rename = "attributeClaims", default, skip_serializing_if = "Option::is_none")]
        pub attribute_claims: Option<serde_json::Value>,
        #[serde(rename = "attributeReport", default, skip_serializing_if = "Option::is_none")]
        pub attribute_report: Option<Vec<sts_model_management_components_4::WithLdapClaimValue2>>,
        #[serde(rename = "attributeClaimPreview", default, skip_serializing_if = "Option::is_none")]
        pub attribute_claim_preview: Option<Vec<Answer200SetsItemAttributeClaimPreviewItem>>,
        /// Partners withholding it, by claim.
        #[serde(rename = "withheldFrom", default, skip_serializing_if = "Option::is_none")]
        pub withheld_from: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttributeChoicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Preview {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
        pub by_ldap: Option<sts_model_management_components_2::DirectoryAttribute>,
        #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
        pub entry_found: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupsPreviewGroupsItem {
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
    pub struct Answer200GroupsPreview {
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
        pub groups: Option<Vec<Answer200GroupsPreviewGroupsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Groups {
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
        pub preview: Option<Answer200GroupsPreview>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WithholdingItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub names: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(rename = "defaultSaml11Namespace", default, skip_serializing_if = "Option::is_none")]
        pub default_saml11_namespace: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub placeholders: Option<Vec<String>>,
        #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
        pub attribute_catalogue: Option<sts_model_management_components_4::WithDescriptionLdapClaim>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub precedence: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sets: Option<Vec<Answer200SetsItem>>,
        #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
        pub attribute_choices: Option<Vec<Answer200AttributeChoicesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preview: Option<Answer200Preview>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Answer200Groups>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub withholding: Option<Vec<Answer200WithholdingItem>>,
    }
}

/// Add one attribute to one set
pub mod add_saml_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/add";
    pub const OPERATION_ID: &str = "addSamlAttribute";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    /// The Kerberos PAC set only (#493): the PAC claim type. Defaults to string;
    /// ignored by the other sets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "string")]
        String,
        #[serde(rename = "int64")]
        Int64,
        #[serde(rename = "uint64")]
        Uint64,
        #[serde(rename = "boolean")]
        Boolean,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub name: String,
        /// May carry a ${...} placeholder.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// The Kerberos PAC set only (#493): the PAC claim type. Defaults to
        /// string; ignored by the other sets.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// The SAML 2.0 set only.
        #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
        pub name_format: Option<String>,
        /// The SAML 1.1 set only. Defaults to the WS-Federation claim namespace,
        /// which is what every relying party already reads.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Add one attribute carrying a directory attribute
pub mod add_saml_directory_attribute_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/add-attribute-claim";
    pub const OPERATION_ID: &str = "addSamlDirectoryAttributeClaim";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    /// The JSON type of each value, in a JWT or UserInfo set. Ignored by the SAML
    /// sets.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "string")]
        String,
        #[serde(rename = "number")]
        Number,
        #[serde(rename = "boolean")]
        Boolean,
        #[serde(rename = "json")]
        Json,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub name: String,
        /// The directory attribute.
        pub attribute: String,
        /// Every value rather than the first.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        /// The JSON type of each value, in a JWT or UserInfo set. Ignored by the
        /// SAML sets.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// The SAML 2.0 set only.
        #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
        pub name_format: Option<String>,
        /// The SAML 1.1 set only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Set which LDAP attributes one set carries
pub mod set_saml_directory_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/attributes";
    pub const OPERATION_ID: &str = "setSamlDirectoryAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        /// LDAP attribute type names, from `attributeCatalogue`. An EMPTY array
        /// clears the selection — and so does an ABSENT one, so a misspelt field
        /// name empties the set rather than being refused. The reply names
        /// everything it `removed` and the audit log keeps a row saying the same,
        /// and `attributes-clear` is how a caller that means it says so.
        pub attributes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Put every catalogued attribute in one set
pub mod select_all_saml_directory_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/attributes-all";
    pub const OPERATION_ID: &str = "selectAllSamlDirectoryAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Take every directory attribute out of one set
pub mod clear_saml_directory_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/attributes-clear";
    pub const OPERATION_ID: &str = "clearSamlDirectoryAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Empty one set
pub mod clear_saml_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/clear";
    pub const OPERATION_ID: &str = "clearSamlAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Remove one attribute from one set
pub mod remove_saml_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/remove";
    pub const OPERATION_ID: &str = "removeSamlAttribute";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Set a whole attribute set at once
pub mod replace_saml_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/saml-attributes/replace";
    pub const OPERATION_ID: &str = "replaceSamlAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: BodySet,
        pub claims: Vec<sts_model_management_components_1::ClaimEntry>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors74;
}

/// Where this realm pushes service accounts' rotated passwords (#221)
pub mod get_secret_destinations {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/secret-destinations";
    pub const OPERATION_ID: &str = "getSecretDestinations";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(rename = "destinationsPage", default, skip_serializing_if = "Option::is_none")]
        pub destinations_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DestinationsItem {
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
        pub location: Option<sts_model_management_components_2::WithProviderPayloadRegion>,
        #[serde(rename = "credentialSet", default, skip_serializing_if = "Option::is_none")]
        pub credential_set: Option<bool>,
        #[serde(rename = "credentialShape", default, skip_serializing_if = "Option::is_none")]
        pub credential_shape: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destinations: Option<Vec<Answer200DestinationsItem>>,
        #[serde(rename = "destinationsPaging", default, skip_serializing_if = "Option::is_none")]
        pub destinations_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payloads: Option<Vec<String>>,
        /// What each provider's credential is.
        #[serde(rename = "credentialShapes", default, skip_serializing_if = "Option::is_none")]
        pub credential_shapes: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "fileAllowed", default, skip_serializing_if = "Option::is_none")]
        pub file_allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
    }
}

/// Add a secret push destination
pub mod add_secret_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/secret-destinations/add-destination";
    pub const OPERATION_ID: &str = "addSecretDestination";

    /// aws, gcp, azure, vault, or file (development mode only).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProvider {
        #[serde(rename = "aws")]
        Aws,
        #[serde(rename = "gcp")]
        Gcp,
        #[serde(rename = "azure")]
        Azure,
        #[serde(rename = "vault")]
        Vault,
        #[serde(rename = "file")]
        File,
    }

    /// password (the bare password) or json ({username, password, realm,
    /// rotatedAt}).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPayload {
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "json")]
        Json,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination's application identifier (add only): the entry it is
        /// filed under in ou=applications.
        pub identifier: String,
        /// What to call it on a page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// aws, gcp, azure, vault, or file (development mode only).
        pub provider: BodyProvider,
        /// password (the bare password) or json ({username, password, realm,
        /// rotatedAt}).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<BodyPayload>,
        /// aws: the region.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub region: Option<String>,
        /// gcp: the project a short secret name is in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub project: Option<String>,
        /// azure: the vault URL; vault: its address. https only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoint: Option<String>,
        /// vault: the KV version 2 mount; secret when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mount: Option<String>,
        /// vault, password payload: the field written; value when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        /// file: the absolute directory a secret name is a file in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<String>,
        /// vault: PEM certificates of the CA its listener chains to.
        #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
        pub ca_certificates: Option<String>,
        /// The WRITE credential, write-only: never returned, drawn or logged. aws:
        /// JSON {accessKeyId, secretAccessKey[, sessionToken]}; gcp: a service
        /// account key's JSON; azure: JSON {tenantId, clientId, clientSecret};
        /// vault: a token. On a change, empty keeps the one set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors177;
}

/// Remove a secret push destination
pub mod remove_secret_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/secret-destinations/remove-destination";
    pub const OPERATION_ID: &str = "removeSecretDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination: its entry's DN, as the register answers it, or its
        /// identifier.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors177;
}

/// Write a canary version to a test secret
pub mod test_secret_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/secret-destinations/test-push";
    pub const OPERATION_ID: &str = "testSecretDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination: its entry's DN, as the register answers it, or its
        /// identifier.
        pub id: String,
        /// The test secret.
        #[serde(rename = "secretName")]
        pub secret_name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors177;
}

/// Change a secret push destination
pub mod update_secret_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/secret-destinations/update-destination";
    pub const OPERATION_ID: &str = "updateSecretDestination";

    /// aws, gcp, azure, vault, or file (development mode only).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProvider {
        #[serde(rename = "aws")]
        Aws,
        #[serde(rename = "gcp")]
        Gcp,
        #[serde(rename = "azure")]
        Azure,
        #[serde(rename = "vault")]
        Vault,
        #[serde(rename = "file")]
        File,
    }

    /// password (the bare password) or json ({username, password, realm,
    /// rotatedAt}).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPayload {
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "json")]
        Json,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination: its entry's DN, as the register answers it, or its
        /// identifier.
        pub id: String,
        /// What to call it on a page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// aws, gcp, azure, vault, or file (development mode only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<BodyProvider>,
        /// password (the bare password) or json ({username, password, realm,
        /// rotatedAt}).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<BodyPayload>,
        /// aws: the region.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub region: Option<String>,
        /// gcp: the project a short secret name is in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub project: Option<String>,
        /// azure: the vault URL; vault: its address. https only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoint: Option<String>,
        /// vault: the KV version 2 mount; secret when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mount: Option<String>,
        /// vault, password payload: the field written; value when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        /// file: the absolute directory a secret name is a file in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<String>,
        /// vault: PEM certificates of the CA its listener chains to.
        #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
        pub ca_certificates: Option<String>,
        /// The WRITE credential, write-only: never returned, drawn or logged. aws:
        /// JSON {accessKeyId, secretAccessKey[, sessionToken]}; gcp: a service
        /// account key's JSON; azure: JSON {tenantId, clientId, clientSecret};
        /// vault: a token. On a change, empty keeps the one set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors177;
}

/// This realm's credential status lists
pub mod get_credential_status {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/vc-status";
    pub const OPERATION_ID: &str = "getCredentialStatus";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub idx: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(rename = "configId", default, skip_serializing_if = "Option::is_none")]
        pub config_id: Option<String>,
        #[serde(rename = "artifactKey", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub artifact_key: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub explicit: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<f64>>,
        #[serde(rename = "allocatedAt", default, skip_serializing_if = "Option::is_none")]
        pub allocated_at: Option<f64>,
        #[serde(rename = "changedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub changed_at: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub via: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub size: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bits: Option<i64>,
        #[serde(rename = "tokenStatusList", default, skip_serializing_if = "Option::is_none")]
        pub token_status_list: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aggregation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bitstring: Option<Vec<String>>,
        #[serde(rename = "ttlS", default, skip_serializing_if = "Option::is_none")]
        pub ttl_s: Option<f64>,
        #[serde(rename = "lifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_s: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allocated: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub invalid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suspended: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(rename = "rowsPaging", default, skip_serializing_if = "Option::is_none")]
        pub rows_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }
}

/// Publish one Bitstring Status List
pub mod publish_status_list {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/vc-status/publish";
    pub const OPERATION_ID: &str = "publishStatusList";

    /// Which list.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPurpose {
        #[serde(rename = "revocation")]
        Revocation,
        #[serde(rename = "suspension")]
        Suspension,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which list.
        pub purpose: BodyPurpose,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors7;
}

/// Reinstate a suspended credential (VALID)
pub mod reinstate_credential {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/vc-status/reinstate";
    pub const OPERATION_ID: &str = "reinstateCredential";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The index, as GET /admin-api/vc-status lists it.
        pub idx: i64,
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
        pub idx: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }
}

/// Revoke one issued credential (INVALID, final)
pub mod revoke_credential {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/vc-status/revoke";
    pub const OPERATION_ID: &str = "revokeCredential";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The index, as GET /admin-api/vc-status lists it.
        pub idx: i64,
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
        pub idx: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }
}

/// Suspend one issued credential (SUSPENDED)
pub mod suspend_credential {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/vc-status/suspend";
    pub const OPERATION_ID: &str = "suspendCredential";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The index, as GET /admin-api/vc-status lists it.
        pub idx: i64,
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
        pub idx: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "addAttributeSource" => Some(serde_json::from_value::<add_attribute_source::Body>(value.clone()).map(|_| ())),
        "refreshAttributeSourcePerson" => Some(serde_json::from_value::<refresh_attribute_source_person::Body>(value.clone()).map(|_| ())),
        "refreshAttributeSource" => Some(serde_json::from_value::<refresh_attribute_source::Body>(value.clone()).map(|_| ())),
        "removeAttributeSource" => Some(serde_json::from_value::<remove_attribute_source::Body>(value.clone()).map(|_| ())),
        "testAttributeSource" => Some(serde_json::from_value::<test_attribute_source::Body>(value.clone()).map(|_| ())),
        "updateAttributeSource" => Some(serde_json::from_value::<update_attribute_source::Body>(value.clone()).map(|_| ())),
        "addClaim" => Some(serde_json::from_value::<add_claim::Body>(value.clone()).map(|_| ())),
        "addAttributeClaim" => Some(serde_json::from_value::<add_attribute_claim::Body>(value.clone()).map(|_| ())),
        "setClaimAttributes" => Some(serde_json::from_value::<set_claim_attributes::Body>(value.clone()).map(|_| ())),
        "selectAllClaimAttributes" => Some(serde_json::from_value::<select_all_claim_attributes::Body>(value.clone()).map(|_| ())),
        "clearClaimAttributes" => Some(serde_json::from_value::<clear_claim_attributes::Body>(value.clone()).map(|_| ())),
        "clearClaims" => Some(serde_json::from_value::<clear_claims::Body>(value.clone()).map(|_| ())),
        "removeClaim" => Some(serde_json::from_value::<remove_claim::Body>(value.clone()).map(|_| ())),
        "replaceClaims" => Some(serde_json::from_value::<replace_claims::Body>(value.clone()).map(|_| ())),
        "forgetUserConsent" => Some(serde_json::from_value::<forget_user_consent::Body>(value.clone()).map(|_| ())),
        "grantGlobalConsent" => Some(serde_json::from_value::<grant_global_consent::Body>(value.clone()).map(|_| ())),
        "revokeApplicationConsent" => Some(serde_json::from_value::<revoke_application_consent::Body>(value.clone()).map(|_| ())),
        "revokeConsent" => Some(serde_json::from_value::<revoke_consent::Body>(value.clone()).map(|_| ())),
        "revokeGlobalConsent" => Some(serde_json::from_value::<revoke_global_consent::Body>(value.clone()).map(|_| ())),
        "addCredentialClaim" => Some(serde_json::from_value::<add_credential_claim::Body>(value.clone()).map(|_| ())),
        "resetCredentialClaims" => Some(serde_json::from_value::<reset_credential_claims::Body>(value.clone()).map(|_| ())),
        "populateDirectory" => Some(serde_json::from_value::<populate_directory::Body>(value.clone()).map(|_| ())),
        "removeCredentialClaim" => Some(serde_json::from_value::<remove_credential_claim::Body>(value.clone()).map(|_| ())),
        "selectCredentialClaims" => Some(serde_json::from_value::<select_credential_claims::Body>(value.clone()).map(|_| ())),
        "reportDeviceCompliance" => Some(serde_json::from_value::<report_device_compliance::Body>(value.clone()).map(|_| ())),
        "addDeviceKey" => Some(serde_json::from_value::<add_device_key::Body>(value.clone()).map(|_| ())),
        "createDevice" => Some(serde_json::from_value::<create_device::Body>(value.clone()).map(|_| ())),
        "removeDevice" => Some(serde_json::from_value::<remove_device::Body>(value.clone()).map(|_| ())),
        "removeDeviceKey" => Some(serde_json::from_value::<remove_device_key::Body>(value.clone()).map(|_| ())),
        "setDeviceCompliance" => Some(serde_json::from_value::<set_device_compliance::Body>(value.clone()).map(|_| ())),
        "setDeviceStatus" => Some(serde_json::from_value::<set_device_status::Body>(value.clone()).map(|_| ())),
        "updateDevice" => Some(serde_json::from_value::<update_device::Body>(value.clone()).map(|_| ())),
        "addEstHostName" => Some(serde_json::from_value::<add_est_host_name::Body>(value.clone()).map(|_| ())),
        "issueEstServerKey" => Some(serde_json::from_value::<issue_est_server_key::Body>(value.clone()).map(|_| ())),
        "removeEstHostName" => Some(serde_json::from_value::<remove_est_host_name::Body>(value.clone()).map(|_| ())),
        "revokeEstCertificate" => Some(serde_json::from_value::<revoke_est_certificate::Body>(value.clone()).map(|_| ())),
        "definePermission" => Some(serde_json::from_value::<define_permission::Body>(value.clone()).map(|_| ())),
        "grantPermission" => Some(serde_json::from_value::<grant_permission::Body>(value.clone()).map(|_| ())),
        "removePermission" => Some(serde_json::from_value::<remove_permission::Body>(value.clone()).map(|_| ())),
        "revokePermission" => Some(serde_json::from_value::<revoke_permission::Body>(value.clone()).map(|_| ())),
        "setPermissionBase" => Some(serde_json::from_value::<set_permission_base::Body>(value.clone()).map(|_| ())),
        "endPostLoginActivity" => Some(serde_json::from_value::<end_post_login_activity::Body>(value.clone()).map(|_| ())),
        "pausePostLoginActivity" => Some(serde_json::from_value::<pause_post_login_activity::Body>(value.clone()).map(|_| ())),
        "resumePostLoginActivity" => Some(serde_json::from_value::<resume_post_login_activity::Body>(value.clone()).map(|_| ())),
        "startPostLoginActivity" => Some(serde_json::from_value::<start_post_login_activity::Body>(value.clone()).map(|_| ())),
        "addSamlAttribute" => Some(serde_json::from_value::<add_saml_attribute::Body>(value.clone()).map(|_| ())),
        "addSamlDirectoryAttributeClaim" => Some(serde_json::from_value::<add_saml_directory_attribute_claim::Body>(value.clone()).map(|_| ())),
        "setSamlDirectoryAttributes" => Some(serde_json::from_value::<set_saml_directory_attributes::Body>(value.clone()).map(|_| ())),
        "selectAllSamlDirectoryAttributes" => Some(serde_json::from_value::<select_all_saml_directory_attributes::Body>(value.clone()).map(|_| ())),
        "clearSamlDirectoryAttributes" => Some(serde_json::from_value::<clear_saml_directory_attributes::Body>(value.clone()).map(|_| ())),
        "clearSamlAttributes" => Some(serde_json::from_value::<clear_saml_attributes::Body>(value.clone()).map(|_| ())),
        "removeSamlAttribute" => Some(serde_json::from_value::<remove_saml_attribute::Body>(value.clone()).map(|_| ())),
        "replaceSamlAttributes" => Some(serde_json::from_value::<replace_saml_attributes::Body>(value.clone()).map(|_| ())),
        "addSecretDestination" => Some(serde_json::from_value::<add_secret_destination::Body>(value.clone()).map(|_| ())),
        "removeSecretDestination" => Some(serde_json::from_value::<remove_secret_destination::Body>(value.clone()).map(|_| ())),
        "testSecretDestination" => Some(serde_json::from_value::<test_secret_destination::Body>(value.clone()).map(|_| ())),
        "updateSecretDestination" => Some(serde_json::from_value::<update_secret_destination::Body>(value.clone()).map(|_| ())),
        "publishStatusList" => Some(serde_json::from_value::<publish_status_list::Body>(value.clone()).map(|_| ())),
        "reinstateCredential" => Some(serde_json::from_value::<reinstate_credential::Body>(value.clone()).map(|_| ())),
        "revokeCredential" => Some(serde_json::from_value::<revoke_credential::Body>(value.clone()).map(|_| ())),
        "suspendCredential" => Some(serde_json::from_value::<suspend_credential::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getAttributeSources", 200) => Some(serde_json::from_value::<get_attribute_sources::Answer200>(value.clone()).map(|_| ())),
        ("addAttributeSource", 200) => Some(serde_json::from_value::<add_attribute_source::Answer200>(value.clone()).map(|_| ())),
        ("refreshAttributeSourcePerson", 200) => Some(serde_json::from_value::<refresh_attribute_source_person::Answer200>(value.clone()).map(|_| ())),
        ("refreshAttributeSource", 200) => Some(serde_json::from_value::<refresh_attribute_source::Answer200>(value.clone()).map(|_| ())),
        ("removeAttributeSource", 200) => Some(serde_json::from_value::<remove_attribute_source::Answer200>(value.clone()).map(|_| ())),
        ("testAttributeSource", 200) => Some(serde_json::from_value::<test_attribute_source::Answer200>(value.clone()).map(|_| ())),
        ("updateAttributeSource", 200) => Some(serde_json::from_value::<update_attribute_source::Answer200>(value.clone()).map(|_| ())),
        ("getClaims", 200) => Some(serde_json::from_value::<get_claims::Answer200>(value.clone()).map(|_| ())),
        ("addClaim", 200) => Some(serde_json::from_value::<add_claim::Answer200>(value.clone()).map(|_| ())),
        ("addAttributeClaim", 200) => Some(serde_json::from_value::<add_attribute_claim::Answer200>(value.clone()).map(|_| ())),
        ("setClaimAttributes", 200) => Some(serde_json::from_value::<set_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("selectAllClaimAttributes", 200) => Some(serde_json::from_value::<select_all_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearClaimAttributes", 200) => Some(serde_json::from_value::<clear_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearClaims", 200) => Some(serde_json::from_value::<clear_claims::Answer200>(value.clone()).map(|_| ())),
        ("removeClaim", 200) => Some(serde_json::from_value::<remove_claim::Answer200>(value.clone()).map(|_| ())),
        ("replaceClaims", 200) => Some(serde_json::from_value::<replace_claims::Answer200>(value.clone()).map(|_| ())),
        ("getConsent", 200) => Some(serde_json::from_value::<get_consent::Answer200>(value.clone()).map(|_| ())),
        ("forgetUserConsent", 200) => Some(serde_json::from_value::<forget_user_consent::Answer200>(value.clone()).map(|_| ())),
        ("grantGlobalConsent", 200) => Some(serde_json::from_value::<grant_global_consent::Answer200>(value.clone()).map(|_| ())),
        ("revokeApplicationConsent", 200) => Some(serde_json::from_value::<revoke_application_consent::Answer200>(value.clone()).map(|_| ())),
        ("revokeConsent", 200) => Some(serde_json::from_value::<revoke_consent::Answer200>(value.clone()).map(|_| ())),
        ("revokeGlobalConsent", 200) => Some(serde_json::from_value::<revoke_global_consent::Answer200>(value.clone()).map(|_| ())),
        ("getCredentialClaims", 200) => Some(serde_json::from_value::<get_credential_claims::Answer200>(value.clone()).map(|_| ())),
        ("addCredentialClaim", 200) => Some(serde_json::from_value::<add_credential_claim::Answer200>(value.clone()).map(|_| ())),
        ("resetCredentialClaims", 200) => Some(serde_json::from_value::<reset_credential_claims::Answer200>(value.clone()).map(|_| ())),
        ("populateDirectory", 200) => Some(serde_json::from_value::<populate_directory::Answer200>(value.clone()).map(|_| ())),
        ("removeCredentialClaim", 200) => Some(serde_json::from_value::<remove_credential_claim::Answer200>(value.clone()).map(|_| ())),
        ("selectCredentialClaims", 200) => Some(serde_json::from_value::<select_credential_claims::Answer200>(value.clone()).map(|_| ())),
        ("getDelegation", 200) => Some(serde_json::from_value::<get_delegation::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationApplication", 200) => Some(serde_json::from_value::<get_delegation_application::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationPolicy", 200) => Some(serde_json::from_value::<get_delegation_policy::Answer200>(value.clone()).map(|_| ())),
        ("getDelegationUser", 200) => Some(serde_json::from_value::<get_delegation_user::Answer200>(value.clone()).map(|_| ())),
        ("reportDeviceCompliance", 200) => Some(serde_json::from_value::<report_device_compliance::Answer200>(value.clone()).map(|_| ())),
        ("getDeviceRegistration", 200) => Some(serde_json::from_value::<get_device_registration::Answer200>(value.clone()).map(|_| ())),
        ("getDevices", 200) => Some(serde_json::from_value::<get_devices::Answer200>(value.clone()).map(|_| ())),
        ("addDeviceKey", 200) => Some(serde_json::from_value::<add_device_key::Answer200>(value.clone()).map(|_| ())),
        ("createDevice", 200) => Some(serde_json::from_value::<create_device::Answer200>(value.clone()).map(|_| ())),
        ("getDevicesMonitor", 200) => Some(serde_json::from_value::<get_devices_monitor::Answer200>(value.clone()).map(|_| ())),
        ("removeDevice", 200) => Some(serde_json::from_value::<remove_device::Answer200>(value.clone()).map(|_| ())),
        ("removeDeviceKey", 200) => Some(serde_json::from_value::<remove_device_key::Answer200>(value.clone()).map(|_| ())),
        ("setDeviceCompliance", 200) => Some(serde_json::from_value::<set_device_compliance::Answer200>(value.clone()).map(|_| ())),
        ("setDeviceStatus", 200) => Some(serde_json::from_value::<set_device_status::Answer200>(value.clone()).map(|_| ())),
        ("updateDevice", 200) => Some(serde_json::from_value::<update_device::Answer200>(value.clone()).map(|_| ())),
        ("getEst", 200) => Some(serde_json::from_value::<get_est::Answer200>(value.clone()).map(|_| ())),
        ("addEstHostName", 200) => Some(serde_json::from_value::<add_est_host_name::Answer200>(value.clone()).map(|_| ())),
        ("issueEstServerKey", 200) => Some(serde_json::from_value::<issue_est_server_key::Answer200>(value.clone()).map(|_| ())),
        ("getEstMonitor", 200) => Some(serde_json::from_value::<get_est_monitor::Answer200>(value.clone()).map(|_| ())),
        ("removeEstHostName", 200) => Some(serde_json::from_value::<remove_est_host_name::Answer200>(value.clone()).map(|_| ())),
        ("revokeEstCertificate", 200) => Some(serde_json::from_value::<revoke_est_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getPermissions", 200) => Some(serde_json::from_value::<get_permissions::Answer200>(value.clone()).map(|_| ())),
        ("definePermission", 200) => Some(serde_json::from_value::<define_permission::Answer200>(value.clone()).map(|_| ())),
        ("grantPermission", 200) => Some(serde_json::from_value::<grant_permission::Answer200>(value.clone()).map(|_| ())),
        ("getPermissionGroups", 200) => Some(serde_json::from_value::<get_permission_groups::Answer200>(value.clone()).map(|_| ())),
        ("removePermission", 200) => Some(serde_json::from_value::<remove_permission::Answer200>(value.clone()).map(|_| ())),
        ("revokePermission", 200) => Some(serde_json::from_value::<revoke_permission::Answer200>(value.clone()).map(|_| ())),
        ("setPermissionBase", 200) => Some(serde_json::from_value::<set_permission_base::Answer200>(value.clone()).map(|_| ())),
        ("getPostLoginActivities", 200) => Some(serde_json::from_value::<get_post_login_activities::Answer200>(value.clone()).map(|_| ())),
        ("endPostLoginActivity", 200) => Some(serde_json::from_value::<end_post_login_activity::Answer200>(value.clone()).map(|_| ())),
        ("pausePostLoginActivity", 200) => Some(serde_json::from_value::<pause_post_login_activity::Answer200>(value.clone()).map(|_| ())),
        ("resumePostLoginActivity", 200) => Some(serde_json::from_value::<resume_post_login_activity::Answer200>(value.clone()).map(|_| ())),
        ("startPostLoginActivity", 200) => Some(serde_json::from_value::<start_post_login_activity::Answer200>(value.clone()).map(|_| ())),
        ("getSamlAttributes", 200) => Some(serde_json::from_value::<get_saml_attributes::Answer200>(value.clone()).map(|_| ())),
        ("addSamlAttribute", 200) => Some(serde_json::from_value::<add_saml_attribute::Answer200>(value.clone()).map(|_| ())),
        ("addSamlDirectoryAttributeClaim", 200) => Some(serde_json::from_value::<add_saml_directory_attribute_claim::Answer200>(value.clone()).map(|_| ())),
        ("setSamlDirectoryAttributes", 200) => Some(serde_json::from_value::<set_saml_directory_attributes::Answer200>(value.clone()).map(|_| ())),
        ("selectAllSamlDirectoryAttributes", 200) => Some(serde_json::from_value::<select_all_saml_directory_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearSamlDirectoryAttributes", 200) => Some(serde_json::from_value::<clear_saml_directory_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearSamlAttributes", 200) => Some(serde_json::from_value::<clear_saml_attributes::Answer200>(value.clone()).map(|_| ())),
        ("removeSamlAttribute", 200) => Some(serde_json::from_value::<remove_saml_attribute::Answer200>(value.clone()).map(|_| ())),
        ("replaceSamlAttributes", 200) => Some(serde_json::from_value::<replace_saml_attributes::Answer200>(value.clone()).map(|_| ())),
        ("getSecretDestinations", 200) => Some(serde_json::from_value::<get_secret_destinations::Answer200>(value.clone()).map(|_| ())),
        ("addSecretDestination", 200) => Some(serde_json::from_value::<add_secret_destination::Answer200>(value.clone()).map(|_| ())),
        ("removeSecretDestination", 200) => Some(serde_json::from_value::<remove_secret_destination::Answer200>(value.clone()).map(|_| ())),
        ("testSecretDestination", 200) => Some(serde_json::from_value::<test_secret_destination::Answer200>(value.clone()).map(|_| ())),
        ("updateSecretDestination", 200) => Some(serde_json::from_value::<update_secret_destination::Answer200>(value.clone()).map(|_| ())),
        ("getCredentialStatus", 200) => Some(serde_json::from_value::<get_credential_status::Answer200>(value.clone()).map(|_| ())),
        ("publishStatusList", 200) => Some(serde_json::from_value::<publish_status_list::Answer200>(value.clone()).map(|_| ())),
        ("reinstateCredential", 200) => Some(serde_json::from_value::<reinstate_credential::Answer200>(value.clone()).map(|_| ())),
        ("revokeCredential", 200) => Some(serde_json::from_value::<revoke_credential::Answer200>(value.clone()).map(|_| ())),
        ("suspendCredential", 200) => Some(serde_json::from_value::<suspend_credential::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
