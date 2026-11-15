// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// The ACME server: directory, Issuing CA, profiles, EAB keys, accounts,
/// certificates, host names, settings
pub mod get_acme {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/acme";
    pub const OPERATION_ID: &str = "getAcme";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "credentialsPage", default, skip_serializing_if = "Option::is_none")]
        pub credentials_page: Option<i64>,
        #[serde(rename = "accountsPage", default, skip_serializing_if = "Option::is_none")]
        pub accounts_page: Option<i64>,
        #[serde(rename = "certificatesPage", default, skip_serializing_if = "Option::is_none")]
        pub certificates_page: Option<i64>,
        #[serde(rename = "hostNamesPage", default, skip_serializing_if = "Option::is_none")]
        pub host_names_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Endpoints {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<String>,
        #[serde(rename = "newNonce", default, skip_serializing_if = "Option::is_none")]
        pub new_nonce: Option<String>,
        #[serde(rename = "newAccount", default, skip_serializing_if = "Option::is_none")]
        pub new_account: Option<String>,
        #[serde(rename = "newOrder", default, skip_serializing_if = "Option::is_none")]
        pub new_order: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub orders: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub order: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub finalize: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorization: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(rename = "revokeCert", default, skip_serializing_if = "Option::is_none")]
        pub revoke_cert: Option<String>,
        #[serde(rename = "keyChange", default, skip_serializing_if = "Option::is_none")]
        pub key_change: Option<String>,
        #[serde(rename = "renewalInfo", default, skip_serializing_if = "Option::is_none")]
        pub renewal_info: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authority {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
        pub signature_alg: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub intermediate: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub root: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub needs: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
        pub is_default: Option<bool>,
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
    pub struct Answer200Mode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub development: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub product: Option<String>,
        #[serde(rename = "inForce", default, skip_serializing_if = "Option::is_none")]
        pub in_force: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EabKeysRowsItemEntry {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EabKeysRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<Answer200EabKeysRowsItemEntry>,
        #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
        pub entry_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
        pub created_by: Option<String>,
        #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "boundAccount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub bound_account: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EabKeys {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200EabKeysRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Accounts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<sts_model_management_components_4::WithIdStatusEntry>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200HostNames {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<sts_model_management_components_4::WithAtOperationOutcome>,
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
        pub directory: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Answer200Endpoints>,
        #[serde(rename = "challengeType", default, skip_serializing_if = "Option::is_none")]
        pub challenge_type: Option<String>,
        #[serde(rename = "identifierTypes", default, skip_serializing_if = "Option::is_none")]
        pub identifier_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authority: Option<Answer200Authority>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ProfilesItem>>,
        #[serde(rename = "refusedProfiles", default, skip_serializing_if = "Option::is_none")]
        pub refused_profiles: Option<Vec<Answer200RefusedProfilesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<Answer200Mode>,
        #[serde(rename = "eabLifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub eab_lifetime_s: Option<f64>,
        #[serde(rename = "eabKeys", default, skip_serializing_if = "Option::is_none")]
        pub eab_keys: Option<Answer200EabKeys>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Answer200Accounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<sts_model_management_components_4::WithPagingRowsEntry2>,
        #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
        pub host_names: Option<Answer200HostNames>,
        #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
        pub revocation_reasons: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Register a host name or address on an entry
pub mod add_acme_host_name {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/acme/add-host-name";
    pub const OPERATION_ID: &str = "addAcmeHostName";

    /// Whether the entry is a person (ou=users) or an application
    /// (ou=applications).
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
        /// Whether the entry is a person (ou=users) or an application
        /// (ou=applications).
        pub kind: BodyKind,
        /// The username of a person, or the identifier of an application, in this
        /// realm.
        pub identifier: String,
        /// A DNS name (a leading *. is a wildcard registered exactly so) or an IP
        /// address.
        #[serde(rename = "hostName")]
        pub host_name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors161;
}

/// Issue an External Account Binding key for a person or application (RFC 8555
/// section 7.3.4)
pub mod create_acme_eab {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/acme/create-eab";
    pub const OPERATION_ID: &str = "createAcmeEab";

    /// Whether the entry is a person (ou=users) or an application
    /// (ou=applications).
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
        /// Whether the entry is a person (ou=users) or an application
        /// (ou=applications).
        pub kind: BodyKind,
        /// The username of a person, or the identifier of an application, in this
        /// realm.
        pub identifier: String,
        /// How long it may wait before binding an account; at most
        /// acme.eabLifetimeS, which is also the default.
        #[serde(rename = "lifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_s: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors158;
}

/// Deactivate an ACME account (RFC 8555 section 7.3.6)
pub mod deactivate_acme_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/acme/deactivate-account";
    pub const OPERATION_ID: &str = "deactivateAcmeAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The account id, from GET /admin-api/acme.
        pub account: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors159;
}

/// Delete an External Account Binding key
pub mod delete_acme_eab {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/acme/delete-eab";
    pub const OPERATION_ID: &str = "deleteAcmeEab";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The key id, from GET /admin-api/acme.
        pub kid: String,
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
        pub kid: Option<String>,
    }
}

/// What the ACME server has done in this realm
pub mod get_acme_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/acme/monitor";
    pub const OPERATION_ID: &str = "getAcmeMonitor";

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
        #[serde(rename = "accountsBound", default, skip_serializing_if = "Option::is_none")]
        pub accounts_bound: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<i64>,
        #[serde(rename = "certificatesHeld", default, skip_serializing_if = "Option::is_none")]
        pub certificates_held: Option<i64>,
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
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
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

/// Remove a registered host name from an entry
pub mod remove_acme_host_name {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/acme/remove-host-name";
    pub const OPERATION_ID: &str = "removeAcmeHostName";

    /// Whether the entry is a person (ou=users) or an application
    /// (ou=applications).
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
        /// Whether the entry is a person (ou=users) or an application
        /// (ou=applications).
        pub kind: BodyKind,
        /// The username of a person, or the identifier of an application, in this
        /// realm.
        pub identifier: String,
        /// The registered name to remove.
        #[serde(rename = "hostName")]
        pub host_name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors161;
}

/// Revoke a certificate issued over ACME
pub mod revoke_acme_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/acme/revoke-certificate";
    pub const OPERATION_ID: &str = "revokeAcmeCertificate";

    /// The RFC 5280 reason; unspecified by default.
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
        /// The serial number in hex.
        pub serial: String,
        /// The RFC 5280 reason; unspecified by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors160;
}

/// Every application this service has been asked about, filtered and paged
pub mod get_applications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/applications";
    pub const OPERATION_ID: &str = "getApplications";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryKind {
        #[serde(rename = "oauth2-client")]
        Oauth2Client,
        #[serde(rename = "oauth2-resource-server")]
        Oauth2ResourceServer,
        #[serde(rename = "oidc-relying-party")]
        OidcRelyingParty,
        #[serde(rename = "saml2-service-provider")]
        Saml2ServiceProvider,
        #[serde(rename = "saml11-relying-party")]
        Saml11RelyingParty,
        #[serde(rename = "wsfed-relying-party")]
        WsfedRelyingParty,
        #[serde(rename = "wstrust-relying-party")]
        WstrustRelyingParty,
        #[serde(rename = "oid4vp-verifier")]
        Oid4vpVerifier,
        #[serde(rename = "federation-identity-provider")]
        FederationIdentityProvider,
        #[serde(rename = "kerberos-service")]
        KerberosService,
        #[serde(rename = "gnap-client")]
        GnapClient,
        #[serde(rename = "gnap-resource-server")]
        GnapResourceServer,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "claimsUser", default, skip_serializing_if = "Option::is_none")]
        pub claims_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<QueryKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclude: Option<Vec<String>>,
        #[serde(rename = "attributesPage", default, skip_serializing_if = "Option::is_none")]
        pub attributes_page: Option<i64>,
        #[serde(rename = "authenticationsPage", default, skip_serializing_if = "Option::is_none")]
        pub authentications_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "observedPage", default, skip_serializing_if = "Option::is_none")]
        pub observed_page: Option<i64>,
        #[serde(rename = "heldPage", default, skip_serializing_if = "Option::is_none")]
        pub held_page: Option<i64>,
        #[serde(rename = "exposedPage", default, skip_serializing_if = "Option::is_none")]
        pub exposed_page: Option<i64>,
        #[serde(rename = "grantedOutPage", default, skip_serializing_if = "Option::is_none")]
        pub granted_out_page: Option<i64>,
        #[serde(rename = "enrolledPage", default, skip_serializing_if = "Option::is_none")]
        pub enrolled_page: Option<i64>,
        #[serde(rename = "enrolledConfigPage", default, skip_serializing_if = "Option::is_none")]
        pub enrolled_config_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::ApplicationList;
}

/// Add a value to a multi-valued attribute
pub mod add_application_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/add";
    pub const OPERATION_ID: &str = "addApplicationValue";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAttribute {
        #[serde(rename = "appCorsOrigin")]
        AppCorsOrigin,
        #[serde(rename = "appAllowedProtocol")]
        AppAllowedProtocol,
        #[serde(rename = "oauthClientId")]
        OauthClientId,
        #[serde(rename = "oauthAudience")]
        OauthAudience,
        #[serde(rename = "oauthRedirectUri")]
        OauthRedirectUri,
        #[serde(rename = "oauthClaimsRedirectUri")]
        OauthClaimsRedirectUri,
        #[serde(rename = "oauthPostLogoutRedirectUri")]
        OauthPostLogoutRedirectUri,
        #[serde(rename = "oauthGrantType")]
        OauthGrantType,
        #[serde(rename = "oauthResponseType")]
        OauthResponseType,
        #[serde(rename = "oauthAllowedTokenResponseTypes")]
        OauthAllowedTokenResponseTypes,
        #[serde(rename = "oauthScope")]
        OauthScope,
        #[serde(rename = "oauthAllowedScope")]
        OauthAllowedScope,
        #[serde(rename = "oauthPermission")]
        OauthPermission,
        #[serde(rename = "oauthRoleGatedPermission")]
        OauthRoleGatedPermission,
        #[serde(rename = "oauthDelegatedPermission")]
        OauthDelegatedPermission,
        #[serde(rename = "oauthGlobalConsent")]
        OauthGlobalConsent,
        #[serde(rename = "oauthTokenEndpointAuthMethod")]
        OauthTokenEndpointAuthMethod,
        #[serde(rename = "oauthRequestUri")]
        OauthRequestUri,
        #[serde(rename = "oauthAuthorizationDetailsType")]
        OauthAuthorizationDetailsType,
        #[serde(rename = "oauthAuthorizationDetailsTypes")]
        OauthAuthorizationDetailsTypes,
        #[serde(rename = "authzenAttribute")]
        AuthzenAttribute,
        #[serde(rename = "appAuthzenApplication")]
        AppAuthzenApplication,
        #[serde(rename = "appAuthzenCallbackUri")]
        AppAuthzenCallbackUri,
        #[serde(rename = "oauthAssertionIssuer")]
        OauthAssertionIssuer,
        #[serde(rename = "oauthSamlAssertionIssuer")]
        OauthSamlAssertionIssuer,
        #[serde(rename = "oauthSoftwareStatementIssuer")]
        OauthSoftwareStatementIssuer,
        #[serde(rename = "samlEntityId")]
        SamlEntityId,
        #[serde(rename = "samlAssertionConsumerService")]
        SamlAssertionConsumerService,
        #[serde(rename = "samlSingleLogoutService")]
        SamlSingleLogoutService,
        #[serde(rename = "samlSigningCertificate")]
        SamlSigningCertificate,
        #[serde(rename = "oauthAccessTokenClaim")]
        OauthAccessTokenClaim,
        #[serde(rename = "appRequiredRole")]
        AppRequiredRole,
        #[serde(rename = "appAllowedToDelegateTo")]
        AppAllowedToDelegateTo,
        #[serde(rename = "appAllowedToActOnBehalfOf")]
        AppAllowedToActOnBehalfOf,
        #[serde(rename = "appDelegationSubjectGroup")]
        AppDelegationSubjectGroup,
        #[serde(rename = "appDelegationSemantics")]
        AppDelegationSemantics,
        #[serde(rename = "wsfedRealm")]
        WsfedRealm,
        #[serde(rename = "wsfedReplyUrl")]
        WsfedReplyUrl,
        #[serde(rename = "wsfedSignOutUri")]
        WsfedSignOutUri,
        #[serde(rename = "wstrustAppliesTo")]
        WstrustAppliesTo,
        #[serde(rename = "wstrustJwtScope")]
        WstrustJwtScope,
        #[serde(rename = "krb5ServicePrincipalName")]
        Krb5ServicePrincipalName,
        #[serde(rename = "krb5S4uSelfRealm")]
        Krb5S4uSelfRealm,
        #[serde(rename = "oid4vpClientId")]
        Oid4vpClientId,
        #[serde(rename = "federationPartnerId")]
        FederationPartnerId,
        #[serde(rename = "ldapBindDn")]
        LdapBindDn,
        #[serde(rename = "scimClientId")]
        ScimClientId,
        #[serde(rename = "acmeAllowedProfiles")]
        AcmeAllowedProfiles,
        #[serde(rename = "estAllowedProfiles")]
        EstAllowedProfiles,
        #[serde(rename = "scepAllowedProfiles")]
        ScepAllowedProfiles,
        #[serde(rename = "didPublicKeyJwk")]
        DidPublicKeyJwk,
        #[serde(rename = "didService")]
        DidService,
        #[serde(rename = "didAlsoKnownAs")]
        DidAlsoKnownAs,
        #[serde(rename = "scimClientScopeGroups")]
        ScimClientScopeGroups,
        #[serde(rename = "scimClientGroups")]
        ScimClientGroups,
        #[serde(rename = "scimClientCells")]
        ScimClientCells,
        #[serde(rename = "ssfReceiverId")]
        SsfReceiverId,
        #[serde(rename = "ssfDeliveryEndpoint")]
        SsfDeliveryEndpoint,
        #[serde(rename = "ssfAllowedEvents")]
        SsfAllowedEvents,
        #[serde(rename = "gnapFinishUri")]
        GnapFinishUri,
        #[serde(rename = "gnapInteractionStartModes")]
        GnapInteractionStartModes,
        #[serde(rename = "gnapAllowedAccess")]
        GnapAllowedAccess,
        #[serde(rename = "gnapResourceServerUri")]
        GnapResourceServerUri,
        #[serde(rename = "spiffeWorkloadId")]
        SpiffeWorkloadId,
        #[serde(rename = "appFederationRelationship")]
        AppFederationRelationship,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub attribute: BodyAttribute,
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors86;
}

/// Store a certificate on an application's entry, so an outside certificate
/// authority's certificate authenticates it
pub mod add_application_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/add-certificate";
    pub const OPERATION_ID: &str = "addApplicationCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application's identifier, exactly as this registry holds it.
        pub application: String,
        /// The leaf, as one PEM block or base64 DER.
        pub certificate: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors101;
}

/// Add one owner to an application
pub mod add_application_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/add-owner";
    pub const OPERATION_ID: &str = "addApplicationOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        /// The person or group to add.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors87;
}

/// Add a client secret beside the ones an application holds
pub mod add_application_client_secret {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/add-secret";
    pub const OPERATION_ID: &str = "addApplicationClientSecret";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(rename = "lifetimeDays", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_days: Option<sts_model_base::unions::IntegerOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors88;
}

/// Take the claims off one of a resource server's own scopes
pub mod clear_application_permission_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/clear-permission-claims";
    pub const OPERATION_ID: &str = "clearApplicationPermissionClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub permission: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors96;
}

/// Confirm a return address a development-mode request recorded
pub mod confirm_application_return_address {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/confirm-address";
    pub const OPERATION_ID: &str = "confirmApplicationReturnAddress";

    /// The return-address attribute the address is on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAttribute {
        #[serde(rename = "oauthRedirectUri")]
        OauthRedirectUri,
        #[serde(rename = "samlAssertionConsumerService")]
        SamlAssertionConsumerService,
        #[serde(rename = "wsfedReplyUrl")]
        WsfedReplyUrl,
        #[serde(rename = "gnapFinishUri")]
        GnapFinishUri,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identifier, exactly as the registry holds it.
        pub application: String,
        /// The return-address attribute the address is on.
        pub attribute: BodyAttribute,
        /// The address, exactly as the entry holds it.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors85;
}

/// Put an application in the registry before it connects
pub mod create_application {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/create";
    pub const OPERATION_ID: &str = "createApplication";

    /// Optional, one of the kinds GET /admin-api/applications/new lists. It is a
    /// claim about what this application IS, which is why a value the registry does
    /// not know is refused rather than recorded. **No console form offers this any
    /// more** and it is still taken here. It was a select on
    /// /admin/applications/new beside the protocol families, which is two
    /// vocabularies for one question — eight kinds against fourteen families, five
    /// of them with no kind at all — and it is DERIVED rather than declared: a kind
    /// is written when a protocol actually recognises the identifier, so a form
    /// choosing one asserted a sighting that had not happened. Prefer `protocols`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "oauth2-client")]
        Oauth2Client,
        #[serde(rename = "oauth2-resource-server")]
        Oauth2ResourceServer,
        #[serde(rename = "oidc-relying-party")]
        OidcRelyingParty,
        #[serde(rename = "saml2-service-provider")]
        Saml2ServiceProvider,
        #[serde(rename = "saml11-relying-party")]
        Saml11RelyingParty,
        #[serde(rename = "wsfed-relying-party")]
        WsfedRelyingParty,
        #[serde(rename = "wstrust-relying-party")]
        WstrustRelyingParty,
        #[serde(rename = "oid4vp-verifier")]
        Oid4vpVerifier,
        #[serde(rename = "federation-identity-provider")]
        FederationIdentityProvider,
        #[serde(rename = "kerberos-service")]
        KerberosService,
        #[serde(rename = "gnap-client")]
        GnapClient,
        #[serde(rename = "gnap-resource-server")]
        GnapResourceServer,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProtocolsItem {
        #[serde(rename = "oauth2")]
        Oauth2,
        #[serde(rename = "oidc")]
        Oidc,
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "wsfed")]
        Wsfed,
        #[serde(rename = "wstrust")]
        Wstrust,
        #[serde(rename = "krb5")]
        Krb5,
        #[serde(rename = "oid4vci")]
        Oid4vci,
        #[serde(rename = "oid4vp")]
        Oid4vp,
        #[serde(rename = "federation")]
        Federation,
        #[serde(rename = "ldap")]
        Ldap,
        #[serde(rename = "scim")]
        Scim,
        #[serde(rename = "spiffe")]
        Spiffe,
        #[serde(rename = "mtls")]
        Mtls,
        #[serde(rename = "ssf")]
        Ssf,
        #[serde(rename = "gnap")]
        Gnap,
        #[serde(rename = "uma")]
        Uma,
        #[serde(rename = "acme")]
        Acme,
        #[serde(rename = "est")]
        Est,
        #[serde(rename = "scep")]
        Scep,
        #[serde(rename = "did")]
        Did,
        #[serde(rename = "secret-destination")]
        SecretDestination,
        #[serde(rename = "scim-client")]
        ScimClient,
        #[serde(rename = "vc")]
        Vc,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client_id, wtrealm, AppliesTo, entityID or service principal name.
        /// One application per identifier whatever protocol brings it, so this is
        /// refused if one is already here.
        pub identifier: String,
        /// Optional friendly name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Optional, one of the kinds GET /admin-api/applications/new lists. It is
        /// a claim about what this application IS, which is why a value the
        /// registry does not know is refused rather than recorded. **No console
        /// form offers this any more** and it is still taken here. It was a select
        /// on /admin/applications/new beside the protocol families, which is two
        /// vocabularies for one question — eight kinds against fourteen families,
        /// five of them with no kind at all — and it is DERIVED rather than
        /// declared: a kind is written when a protocol actually recognises the
        /// identifier, so a form choosing one asserted a sighting that had not
        /// happened. Prefer `protocols`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKind>,
        /// THE PROTOCOL FAMILIES THIS APPLICATION IS DECLARED FOR, as ids from the
        /// closed vocabulary GET /admin-api/applications/new publishes. They land
        /// on `appAllowedProtocol`, and one that is not in that list is REFUSED
        /// rather than recorded — a typo that silently became a new family is how
        /// one application comes to be declared for two spellings of one thing.
        /// **IT GRANTS AND REFUSES NOTHING.** Nothing in this service reads the
        /// attribute: an application declared for `saml2` alone is still issued an
        /// access token at /oauth2/token, and one declared for nothing is treated
        /// exactly as it would have been. It is a record of INTENT, kept apart from
        /// `appProtocol` — which is what has actually happened and is not editable
        /// — so the two lists on an entry can be read against each other. A
        /// form-encoded body may repeat `protocol` instead, which is how the
        /// console's checkbox column posts it, and a single string may carry
        /// several separated by spaces or commas. A COMBINED CHOICE the console
        /// draws as one checkbox stands for its families: `vc` declares `oid4vci`
        /// and `oid4vp`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<BodyProtocolsItem>>,
        /// THE ATTRIBUTES THE ENTRY IS CREATED WITH, keyed by the schema's own
        /// attribute name and valued with a string or an array of strings. This is
        /// where the per-protocol identifiers and the redirect URIs go —
        /// `oauthClientId`, `samlEntityId`, `wsfedRealm`,
        /// `krb5ServicePrincipalName`, `oauthRedirectUri`,
        /// `samlAssertionConsumerService`, `wsfedReplyUrl` and the rest. GET
        /// /admin-api/applications/new publishes the list as `declarations`, with
        /// the families each attribute serves and whether it holds a list; it is
        /// the same walk of the protocol table the console's form is drawn from, so
        /// this document and that page cannot offer different fields. GET
        /// /admin/ldap/applications publishes every attribute in the schema with an
        /// `editable` member. **Only DECLARED attributes may be given.** A derived
        /// one — a counter, a sighting, `appProtocol`, `appRedirectUriObserved` —
        /// is REFUSED by name rather than written, because an entry created with
        /// one would be asserting a past it does not have. A single-valued
        /// attribute given several values is refused as well, rather than truncated
        /// to the first: the only one you are likely to meet is
        /// `oauthTlsClientAuthSubjectDn`, which an RFC 8705 check compares by exact
        /// string equality, and quietly keeping one of two is exactly the wrong
        /// answer there. **Nothing given here is CHECKED except the OAuth redirect
        /// URIs, and those only in RFC 9700 mode.** The rest are recorded, in the
        /// way being in this registry at all is a record. **106 attributes are
        /// scoped to a PROTOCOL FAMILY and REFUSED on an application declared for
        /// none of them: `oauthNativeSso` (OpenID Connect), `oauthNativeSsoGroup`
        /// (OpenID Connect), `oauthBackchannelTokenDeliveryMode` (OpenID Connect),
        /// `oauthBackchannelClientNotificationEndpoint` (OpenID Connect),
        /// `oauthCommandEndpoint` (OpenID Connect),
        /// `oauthBackchannelAuthenticationRequestSigningAlg` (OpenID Connect),
        /// `oauthBackchannelUserCodeParameter` (OpenID Connect), `oauthSubjectType`
        /// (OpenID Connect), `oauthSectorIdentifierUri` (OpenID Connect),
        /// `oauthDidClaimWithPairwise` (OpenID Connect),
        /// `oauthTokenEndpointAuthSigningAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthIntrospectionSignedResponseAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthIntrospectionEncryptedResponseAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthIntrospectionEncryptedResponseEnc` (OAuth 2.0, OpenID Connect),
        /// `oauthRequestUri` (OAuth 2.0, OpenID Connect),
        /// `oauthRequestObjectSigningAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthRequestObjectEncryptionAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthRequestObjectEncryptionEnc` (OAuth 2.0, OpenID Connect),
        /// `oauthRequireSignedRequestObject` (OAuth 2.0, OpenID Connect),
        /// `oauthRequirePushedAuthorizationRequests` (OAuth 2.0, OpenID Connect),
        /// `oauthHttpSignedRequests` (OAuth 2.0, OpenID Connect),
        /// `oauthAuthorizationDetailsType` (OAuth 2.0, OpenID Connect, GNAP),
        /// `oauthAuthorizationDetailsTypes` (OAuth 2.0, OpenID Connect),
        /// `authzenAttribute` (OAuth 2.0, OpenID Connect), `appAuthzenApplication`
        /// (OAuth 2.0, OpenID Connect), `appAuthzenCallbackUri` (OAuth 2.0, OpenID
        /// Connect), `oauthStepUpAcrValues` (OAuth 2.0, OpenID Connect),
        /// `oauthStepUpMaxAge` (OAuth 2.0, OpenID Connect),
        /// `oauthIdTokenSignedResponseAlg` (OpenID Connect),
        /// `oauthIdTokenEncryptedResponseAlg` (OpenID Connect),
        /// `oauthIdTokenEncryptedResponseEnc` (OpenID Connect),
        /// `oauthUserinfoSignedResponseAlg` (OpenID Connect),
        /// `oauthUserinfoEncryptedResponseAlg` (OpenID Connect),
        /// `oauthUserinfoEncryptedResponseEnc` (OpenID Connect),
        /// `oauthAuthorizationSignedResponseAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthAuthorizationEncryptedResponseAlg` (OAuth 2.0, OpenID Connect),
        /// `oauthAuthorizationEncryptedResponseEnc` (OAuth 2.0, OpenID Connect),
        /// `oauthDefaultAcrValues` (OpenID Connect), `oauthDefaultMaxAge` (OpenID
        /// Connect), `oauthThirdPartyInitiatedLogin` (OAuth 2.0, OpenID Connect),
        /// `oauthSpInitiatedSso` (OAuth 2.0, OpenID Connect),
        /// `oauthInitiateLoginUri` (OAuth 2.0, OpenID Connect), `oauthLogoUri`
        /// (OAuth 2.0, OpenID Connect), `oauthPolicyUri` (OAuth 2.0, OpenID
        /// Connect), `oauthTosUri` (OAuth 2.0, OpenID Connect),
        /// `oauthTokenExchangeRefreshToken` (OAuth 2.0, OpenID Connect),
        /// `vcCredentialClaimAttributes` (OpenID4VCI), `wstrustJwtScope`
        /// (WS-Trust), `krb5S4uSelfRealm` (Kerberos v5), `krb5ForeignTgtDelegation`
        /// (Kerberos v5), `secretDestProvider` (Secret push destination),
        /// `secretDestPayload` (Secret push destination), `secretDestRegion`
        /// (Secret push destination), `secretDestProject` (Secret push
        /// destination), `secretDestEndpoint` (Secret push destination),
        /// `secretDestMount` (Secret push destination), `secretDestField` (Secret
        /// push destination), `secretDestDirectory` (Secret push destination),
        /// `secretDestCaCertificates` (Secret push destination),
        /// `secretDestCredential` (Secret push destination), `scimClientBaseUrl`
        /// (SCIM client (outbound provisioning)), `scimClientEnabled` (SCIM client
        /// (outbound provisioning)), `scimClientAuthMethod` (SCIM client (outbound
        /// provisioning)), `scimClientUsername` (SCIM client (outbound
        /// provisioning)), `scimClientPassword` (SCIM client (outbound
        /// provisioning)), `scimClientTokenEndpoint` (SCIM client (outbound
        /// provisioning)), `scimClientOAuthClientId` (SCIM client (outbound
        /// provisioning)), `scimClientOAuthClientSecret` (SCIM client (outbound
        /// provisioning)), `scimClientOAuthClientAuth` (SCIM client (outbound
        /// provisioning)), `scimClientOAuthScope` (SCIM client (outbound
        /// provisioning)), `scimClientOAuthResource` (SCIM client (outbound
        /// provisioning)), `scimClientTlsSource` (SCIM client (outbound
        /// provisioning)), `scimClientTlsCertificate` (SCIM client (outbound
        /// provisioning)), `scimClientTlsPrivateKey` (SCIM client (outbound
        /// provisioning)), `scimClientCaCertificates` (SCIM client (outbound
        /// provisioning)), `scimClientScopeMode` (SCIM client (outbound
        /// provisioning)), `scimClientScopeGroups` (SCIM client (outbound
        /// provisioning)), `scimClientScopeFilter` (SCIM client (outbound
        /// provisioning)), `scimClientGroupMode` (SCIM client (outbound
        /// provisioning)), `scimClientGroups` (SCIM client (outbound
        /// provisioning)), `scimClientDeprovision` (SCIM client (outbound
        /// provisioning)), `scimClientReconcileMinutes` (SCIM client (outbound
        /// provisioning)), `scimClientJurisdiction` (SCIM client (outbound
        /// provisioning)), `scimClientCells` (SCIM client (outbound provisioning)),
        /// `scimClientMaxRequestsPerSecond` (SCIM client (outbound provisioning)),
        /// `ssfAllowedEvents` (Shared Signals), `ssfCaepIncludeReasons` (Shared
        /// Signals), `ssfCaepReasonLanguage` (Shared Signals),
        /// `ssfCaepOmitEventTimestamp` (Shared Signals), `ssfRiscIncludeReasons`
        /// (Shared Signals), `ssfRiscReasonLanguage` (Shared Signals),
        /// `ssfRiscOmitEventTimestamp` (Shared Signals), `ssfSigningAlgorithm`
        /// (Shared Signals), `ssfMinVerificationInterval` (Shared Signals),
        /// `ssfInactivityTimeoutS` (Shared Signals), `ssfInactivityAction` (Shared
        /// Signals), `ssfVerificationEveryS` (Shared Signals),
        /// `ssfStreamStatusOnCreate` (Shared Signals), `ssfMaxStreams` (Shared
        /// Signals), `ssfMaxSubjectsPerStream` (Shared Signals),
        /// `ssfMaxQueuedEvents` (Shared Signals), `ssfPollMaxEvents` (Shared
        /// Signals), `ssfDeadLetterMaxPerStream` (Shared Signals),
        /// `ssfPushTimeoutMs` (Shared Signals), `ssfPushRetries` (Shared Signals),
        /// `ssfPushRetryDelayMs` (Shared Signals).** That is unlike every other
        /// attribute here, which is inert rather than wrong on an entry that never
        /// reaches the protocol it belongs to — these decide what an ENDPOINT does
        /// for an identifier, so on an entry no request could ever name they would
        /// read as a policy that was in force. Declare the family first
        /// (`protocols` on the create, or add to `appAllowedProtocol`). Clearing
        /// one is never refused, and `ldapmodify` reaches them like every other
        /// attribute.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
        /// The lifetime of the client secret the create carries in
        /// `fields.oauthClientSecret` (#394), as `add-secret` takes it: whole days,
        /// 0 to 730, 0 never expiring; omitted or empty,
        /// `oauth2.clientSecretLifetimeDays` (`defaultSecretLifetimeDays` in GET
        /// /admin-api/applications/new). It is stamped on the secret's record as
        /// its `expires`. A lifetime outside that range is refused, and so is one
        /// given with no secret, or with a whole secret record, which keeps the
        /// expiry it carries.
        #[serde(rename = "lifetimeDays", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_days: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors85;
}

/// Discard a return address a development-mode request recorded
pub mod discard_application_return_address {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/discard-address";
    pub const OPERATION_ID: &str = "discardApplicationReturnAddress";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAttribute {
        #[serde(rename = "oauthRedirectUri")]
        OauthRedirectUri,
        #[serde(rename = "samlAssertionConsumerService")]
        SamlAssertionConsumerService,
        #[serde(rename = "wsfedReplyUrl")]
        WsfedReplyUrl,
        #[serde(rename = "gnapFinishUri")]
        GnapFinishUri,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub attribute: BodyAttribute,
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors85;
}

/// Export one application's entry as an LDIF file
pub mod export_application_ldif {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/export-ldif";
    pub const OPERATION_ID: &str = "exportApplicationLdif";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyCredentialsV1 {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyCredentials {
        V1(BodyCredentialsV1),
        Bool(bool),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        /// Include credential material, UNENCRYPTED. False when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<BodyCredentials>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors105;
}

/// Give an application its default fine-grained authorization policy
pub mod create_application_fga_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/fga-create-policy";
    pub const OPERATION_ID: &str = "createApplicationFgaPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors98;
}

/// Stop enforcing an application's fine-grained authorization policy
pub mod disable_application_fga {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/fga-disable";
    pub const OPERATION_ID: &str = "disableApplicationFga";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors98;
}

/// Enforce an application's fine-grained authorization policy
pub mod enable_application_fga {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/fga-enable";
    pub const OPERATION_ID: &str = "enableApplicationFga";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors98;
}

/// Reset an application's fine-grained authorization policy to the default
pub mod reset_application_fga_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/fga-reset-policy";
    pub const OPERATION_ID: &str = "resetApplicationFgaPolicy";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyConfirmV1 {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyConfirm {
        V1(BodyConfirmV1),
        Bool(bool),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        /// The rewrite is meant.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<BodyConfirm>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors98;
}

/// Delete an application entry entirely
pub mod delete_application {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/forget";
    pub const OPERATION_ID: &str = "deleteApplication";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors85;
}

/// Generate a key pair for an application's DID, publishing the public half
pub mod generate_application_did_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/generate-did-key";
    pub const OPERATION_ID: &str = "generateApplicationDidKey";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAlgorithm {
        #[serde(rename = "ES256")]
        Es256,
        #[serde(rename = "ES384")]
        Es384,
        #[serde(rename = "EdDSA")]
        EdDsa,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<BodyAlgorithm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replace: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors90;
}

/// Create an application from an LDIF file
pub mod import_application_ldif {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/import-ldif";
    pub const OPERATION_ID: &str = "importApplicationLdif";

    /// An uploaded LDIF file: its name and its text.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyFile {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        pub text: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The LDIF document.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ldif: Option<String>,
        /// An uploaded LDIF file: its name and its text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<BodyFile>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors85;
}

/// Return an application to the realm's directory-attribute selection for a set
pub mod inherit_application_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/inherit-claim-attributes";
    pub const OPERATION_ID: &str = "inheritApplicationClaimAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "userinfo")]
        Userinfo,
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "credential")]
        Credential,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub set: BodySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors94;
}

/// Issue an application a message-signing certificate from this realm's CA
pub mod issue_application_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/issue-signing-certificate";
    pub const OPERATION_ID: &str = "issueApplicationSigningCertificate";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors99;
}

/// Sign a software statement for an application, as this realm
pub mod issue_application_software_statement {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/issue-software-statement";
    pub const OPERATION_ID: &str = "issueApplicationSoftwareStatement";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The publisher's identifier, exactly as the registry holds it.
        pub application: String,
        /// The client metadata the statement fixes, as an object or as JSON text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metadata: Option<sts_model_base::unions::StringOrObject>,
        /// Seconds until `exp`; 0 for no expiry. Defaults to
        /// oauth2.softwareStatementLifetimeS.
        #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_seconds: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors102;
}

/// Issue an application a TLS client certificate from this realm's CA
pub mod issue_application_tls_client_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/issue-tls-client-certificate";
    pub const OPERATION_ID: &str = "issueApplicationTlsClientCertificate";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors99;
}

/// Read an RFC 9728 protected resource metadata document and answer with the
/// application it describes
pub mod load_protected_resource_metadata {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/load-resource-metadata";
    pub const OPERATION_ID: &str = "loadProtectedResourceMetadata";

    /// An uploaded document: its file name and its text, which is how the console
    /// sends the file it was given.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyFile {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        pub text: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The protected resource metadata document, as JSON text or as a JSON
        /// object.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<sts_model_base::unions::StringOrObject>,
        /// Where the document is published, usually
        /// `https://<host>/.well-known/oauth-protected-resource[/<path>]`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// An uploaded document: its file name and its text, which is how the
        /// console sends the file it was given.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<BodyFile>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors104;
}

/// The vocabulary a new application may be created with, and where it would
/// land
pub mod get_new_application_form {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/applications/new";
    pub const OPERATION_ID: &str = "getNewApplicationForm";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::NewApplicationForm;
}

/// Fetch this service provider's SAML metadata and consume it
pub mod refresh_application_metadata {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/refresh-metadata";
    pub const OPERATION_ID: &str = "refreshApplicationMetadata";

    /// The application whose metadata should be refreshed.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors103;
}

/// Mint a new client secret for an application, replacing every one it holds
pub mod regenerate_application_client_secret {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/regenerate-secret";
    pub const OPERATION_ID: &str = "regenerateApplicationClientSecret";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors88;
}

/// Remove a value from a multi-valued attribute
pub mod remove_application_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove";
    pub const OPERATION_ID: &str = "removeApplicationValue";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAttribute {
        #[serde(rename = "appCorsOrigin")]
        AppCorsOrigin,
        #[serde(rename = "appAllowedProtocol")]
        AppAllowedProtocol,
        #[serde(rename = "oauthClientId")]
        OauthClientId,
        #[serde(rename = "oauthAudience")]
        OauthAudience,
        #[serde(rename = "oauthRedirectUri")]
        OauthRedirectUri,
        #[serde(rename = "oauthClaimsRedirectUri")]
        OauthClaimsRedirectUri,
        #[serde(rename = "oauthPostLogoutRedirectUri")]
        OauthPostLogoutRedirectUri,
        #[serde(rename = "oauthGrantType")]
        OauthGrantType,
        #[serde(rename = "oauthResponseType")]
        OauthResponseType,
        #[serde(rename = "oauthAllowedTokenResponseTypes")]
        OauthAllowedTokenResponseTypes,
        #[serde(rename = "oauthScope")]
        OauthScope,
        #[serde(rename = "oauthAllowedScope")]
        OauthAllowedScope,
        #[serde(rename = "oauthPermission")]
        OauthPermission,
        #[serde(rename = "oauthRoleGatedPermission")]
        OauthRoleGatedPermission,
        #[serde(rename = "oauthDelegatedPermission")]
        OauthDelegatedPermission,
        #[serde(rename = "oauthGlobalConsent")]
        OauthGlobalConsent,
        #[serde(rename = "oauthTokenEndpointAuthMethod")]
        OauthTokenEndpointAuthMethod,
        #[serde(rename = "oauthRequestUri")]
        OauthRequestUri,
        #[serde(rename = "oauthAuthorizationDetailsType")]
        OauthAuthorizationDetailsType,
        #[serde(rename = "oauthAuthorizationDetailsTypes")]
        OauthAuthorizationDetailsTypes,
        #[serde(rename = "authzenAttribute")]
        AuthzenAttribute,
        #[serde(rename = "appAuthzenApplication")]
        AppAuthzenApplication,
        #[serde(rename = "appAuthzenCallbackUri")]
        AppAuthzenCallbackUri,
        #[serde(rename = "oauthAssertionIssuer")]
        OauthAssertionIssuer,
        #[serde(rename = "oauthSamlAssertionIssuer")]
        OauthSamlAssertionIssuer,
        #[serde(rename = "oauthSoftwareStatementIssuer")]
        OauthSoftwareStatementIssuer,
        #[serde(rename = "samlEntityId")]
        SamlEntityId,
        #[serde(rename = "samlAssertionConsumerService")]
        SamlAssertionConsumerService,
        #[serde(rename = "samlSingleLogoutService")]
        SamlSingleLogoutService,
        #[serde(rename = "samlSigningCertificate")]
        SamlSigningCertificate,
        #[serde(rename = "oauthAccessTokenClaim")]
        OauthAccessTokenClaim,
        #[serde(rename = "appRequiredRole")]
        AppRequiredRole,
        #[serde(rename = "appAllowedToDelegateTo")]
        AppAllowedToDelegateTo,
        #[serde(rename = "appAllowedToActOnBehalfOf")]
        AppAllowedToActOnBehalfOf,
        #[serde(rename = "appDelegationSubjectGroup")]
        AppDelegationSubjectGroup,
        #[serde(rename = "appDelegationSemantics")]
        AppDelegationSemantics,
        #[serde(rename = "wsfedRealm")]
        WsfedRealm,
        #[serde(rename = "wsfedReplyUrl")]
        WsfedReplyUrl,
        #[serde(rename = "wsfedSignOutUri")]
        WsfedSignOutUri,
        #[serde(rename = "wstrustAppliesTo")]
        WstrustAppliesTo,
        #[serde(rename = "wstrustJwtScope")]
        WstrustJwtScope,
        #[serde(rename = "krb5ServicePrincipalName")]
        Krb5ServicePrincipalName,
        #[serde(rename = "krb5S4uSelfRealm")]
        Krb5S4uSelfRealm,
        #[serde(rename = "oid4vpClientId")]
        Oid4vpClientId,
        #[serde(rename = "federationPartnerId")]
        FederationPartnerId,
        #[serde(rename = "ldapBindDn")]
        LdapBindDn,
        #[serde(rename = "scimClientId")]
        ScimClientId,
        #[serde(rename = "acmeAllowedProfiles")]
        AcmeAllowedProfiles,
        #[serde(rename = "estAllowedProfiles")]
        EstAllowedProfiles,
        #[serde(rename = "scepAllowedProfiles")]
        ScepAllowedProfiles,
        #[serde(rename = "didPublicKeyJwk")]
        DidPublicKeyJwk,
        #[serde(rename = "didService")]
        DidService,
        #[serde(rename = "didAlsoKnownAs")]
        DidAlsoKnownAs,
        #[serde(rename = "scimClientScopeGroups")]
        ScimClientScopeGroups,
        #[serde(rename = "scimClientGroups")]
        ScimClientGroups,
        #[serde(rename = "scimClientCells")]
        ScimClientCells,
        #[serde(rename = "ssfReceiverId")]
        SsfReceiverId,
        #[serde(rename = "ssfDeliveryEndpoint")]
        SsfDeliveryEndpoint,
        #[serde(rename = "ssfAllowedEvents")]
        SsfAllowedEvents,
        #[serde(rename = "gnapFinishUri")]
        GnapFinishUri,
        #[serde(rename = "gnapInteractionStartModes")]
        GnapInteractionStartModes,
        #[serde(rename = "gnapAllowedAccess")]
        GnapAllowedAccess,
        #[serde(rename = "gnapResourceServerUri")]
        GnapResourceServerUri,
        #[serde(rename = "spiffeWorkloadId")]
        SpiffeWorkloadId,
        #[serde(rename = "appFederationRelationship")]
        AppFederationRelationship,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub attribute: BodyAttribute,
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors86;
}

/// Take an access type off a resource application
pub mod remove_application_access_type {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove-access-type";
    pub const OPERATION_ID: &str = "removeApplicationAccessType";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(rename = "type")]
        pub type_: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors97;
}

/// Take one row off an access type's XACML mapping
pub mod remove_application_access_type_row {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove-access-type-row";
    pub const OPERATION_ID: &str = "removeApplicationAccessTypeRow";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(rename = "type")]
        pub type_: String,
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors97;
}

/// Take a stored certificate off an application's entry
pub mod remove_application_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove-certificate";
    pub const OPERATION_ID: &str = "removeApplicationCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application's identifier, exactly as this registry holds it.
        pub application: String,
        /// The SHA-256 of the certificate's DER, hex.
        pub sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors101;
}

/// Take one of an application's own custom claims or SAML attributes off
pub mod remove_application_custom_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove-custom-claim";
    pub const OPERATION_ID: &str = "removeApplicationCustomClaim";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "userinfo")]
        Userinfo,
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "kerberos-pac")]
        KerberosPac,
        #[serde(rename = "gnap_access_token")]
        GnapAccessToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub set: BodySet,
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors93;
}

/// Take one owner off an application
pub mod remove_application_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove-owner";
    pub const OPERATION_ID: &str = "removeApplicationOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        /// The owner's DN.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors87;
}

/// Remove one client secret, by its id
pub mod remove_application_client_secret {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/remove-secret";
    pub const OPERATION_ID: &str = "removeApplicationClientSecret";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub secret: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors88;
}

/// Hand back one credential of an application: a client secret by its id, the
/// registration access token, or a sealed key by its attribute
pub mod reveal_application_secret {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/reveal-secret";
    pub const OPERATION_ID: &str = "revealApplicationSecret";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub secret: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors89;
}

/// Withdraw an RFC 7591 registration, keeping the entry
pub mod revoke_application_registration {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/revoke-registration";
    pub const OPERATION_ID: &str = "revokeApplicationRegistration";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors85;
}

/// Revoke one of an application's message-signing certificates
pub mod revoke_application_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/revoke-signing-certificate";
    pub const OPERATION_ID: &str = "revokeApplicationSigningCertificate";

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
        pub application: String,
        #[serde(rename = "serialHex")]
        pub serial_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors100;
}

/// Revoke one of an application's TLS client certificates
pub mod revoke_application_tls_client_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/revoke-tls-client-certificate";
    pub const OPERATION_ID: &str = "revokeApplicationTlsClientCertificate";

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
        pub application: String,
        #[serde(rename = "serialHex")]
        pub serial_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors100;
}

/// Add a new client secret, keeping the others working for an overlap
pub mod rotate_application_client_secret {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/rotate-secret";
    pub const OPERATION_ID: &str = "rotateApplicationClientSecret";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors88;
}

/// Set a single-valued attribute
pub mod set_application_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set";
    pub const OPERATION_ID: &str = "setApplicationAttribute";

    /// One of the editable single-valued attributes. GET /admin/ldap/applications
    /// publishes the schema with an `editable` member on every row.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAttribute {
        #[serde(rename = "appName")]
        AppName,
        #[serde(rename = "appHomePageUrl")]
        AppHomePageUrl,
        #[serde(rename = "appLaunchProtocol")]
        AppLaunchProtocol,
        #[serde(rename = "description")]
        Description,
        #[serde(rename = "oauthClientSecret")]
        OauthClientSecret,
        #[serde(rename = "oauthFrontchannelLogoutUri")]
        OauthFrontchannelLogoutUri,
        #[serde(rename = "oauthFrontchannelLogoutSessionRequired")]
        OauthFrontchannelLogoutSessionRequired,
        #[serde(rename = "oauthBackchannelLogoutUri")]
        OauthBackchannelLogoutUri,
        #[serde(rename = "oauthBackchannelLogoutSessionRequired")]
        OauthBackchannelLogoutSessionRequired,
        #[serde(rename = "oauthPermissionBaseUri")]
        OauthPermissionBaseUri,
        #[serde(rename = "oauthResourceMetadata")]
        OauthResourceMetadata,
        #[serde(rename = "oauthResourceMetadataUrl")]
        OauthResourceMetadataUrl,
        #[serde(rename = "oauthNativeSso")]
        OauthNativeSso,
        #[serde(rename = "oauthNativeSsoGroup")]
        OauthNativeSsoGroup,
        #[serde(rename = "oauthBackchannelTokenDeliveryMode")]
        OauthBackchannelTokenDeliveryMode,
        #[serde(rename = "oauthBackchannelClientNotificationEndpoint")]
        OauthBackchannelClientNotificationEndpoint,
        #[serde(rename = "oauthCommandEndpoint")]
        OauthCommandEndpoint,
        #[serde(rename = "oauthBackchannelAuthenticationRequestSigningAlg")]
        OauthBackchannelAuthenticationRequestSigningAlg,
        #[serde(rename = "oauthBackchannelUserCodeParameter")]
        OauthBackchannelUserCodeParameter,
        #[serde(rename = "oauthSubjectType")]
        OauthSubjectType,
        #[serde(rename = "oauthSectorIdentifierUri")]
        OauthSectorIdentifierUri,
        #[serde(rename = "oauthDidClaimWithPairwise")]
        OauthDidClaimWithPairwise,
        #[serde(rename = "oauthTokenEndpointAuthSigningAlg")]
        OauthTokenEndpointAuthSigningAlg,
        #[serde(rename = "oauthJwks")]
        OauthJwks,
        #[serde(rename = "oauthJwksUri")]
        OauthJwksUri,
        #[serde(rename = "oauthIntrospectionSignedResponseAlg")]
        OauthIntrospectionSignedResponseAlg,
        #[serde(rename = "oauthIntrospectionEncryptedResponseAlg")]
        OauthIntrospectionEncryptedResponseAlg,
        #[serde(rename = "oauthIntrospectionEncryptedResponseEnc")]
        OauthIntrospectionEncryptedResponseEnc,
        #[serde(rename = "oauthRequestObjectSigningAlg")]
        OauthRequestObjectSigningAlg,
        #[serde(rename = "oauthRequestObjectEncryptionAlg")]
        OauthRequestObjectEncryptionAlg,
        #[serde(rename = "oauthRequestObjectEncryptionEnc")]
        OauthRequestObjectEncryptionEnc,
        #[serde(rename = "oauthRequireSignedRequestObject")]
        OauthRequireSignedRequestObject,
        #[serde(rename = "oauthRequirePushedAuthorizationRequests")]
        OauthRequirePushedAuthorizationRequests,
        #[serde(rename = "oauthHttpSignedRequests")]
        OauthHttpSignedRequests,
        #[serde(rename = "oauthStepUpAcrValues")]
        OauthStepUpAcrValues,
        #[serde(rename = "oauthStepUpMaxAge")]
        OauthStepUpMaxAge,
        #[serde(rename = "oauthIdTokenSignedResponseAlg")]
        OauthIdTokenSignedResponseAlg,
        #[serde(rename = "oauthIdTokenEncryptedResponseAlg")]
        OauthIdTokenEncryptedResponseAlg,
        #[serde(rename = "oauthIdTokenEncryptedResponseEnc")]
        OauthIdTokenEncryptedResponseEnc,
        #[serde(rename = "oauthUserinfoSignedResponseAlg")]
        OauthUserinfoSignedResponseAlg,
        #[serde(rename = "oauthUserinfoEncryptedResponseAlg")]
        OauthUserinfoEncryptedResponseAlg,
        #[serde(rename = "oauthUserinfoEncryptedResponseEnc")]
        OauthUserinfoEncryptedResponseEnc,
        #[serde(rename = "oauthAuthorizationSignedResponseAlg")]
        OauthAuthorizationSignedResponseAlg,
        #[serde(rename = "oauthAuthorizationEncryptedResponseAlg")]
        OauthAuthorizationEncryptedResponseAlg,
        #[serde(rename = "oauthAuthorizationEncryptedResponseEnc")]
        OauthAuthorizationEncryptedResponseEnc,
        #[serde(rename = "oauthDefaultAcrValues")]
        OauthDefaultAcrValues,
        #[serde(rename = "oauthDefaultMaxAge")]
        OauthDefaultMaxAge,
        #[serde(rename = "oauthAssertionJwks")]
        OauthAssertionJwks,
        #[serde(rename = "oauthAssertionCertificate")]
        OauthAssertionCertificate,
        #[serde(rename = "oauthAssertionCertificateChain")]
        OauthAssertionCertificateChain,
        #[serde(rename = "oauthAssertionPrivateKey")]
        OauthAssertionPrivateKey,
        #[serde(rename = "oauthAssertionKid")]
        OauthAssertionKid,
        #[serde(rename = "oauthAssertionExpiresAt")]
        OauthAssertionExpiresAt,
        #[serde(rename = "oauthAssertionKeySource")]
        OauthAssertionKeySource,
        #[serde(rename = "oauthSamlAssertionSigningCertificate")]
        OauthSamlAssertionSigningCertificate,
        #[serde(rename = "oauthSamlAssertionCertificate")]
        OauthSamlAssertionCertificate,
        #[serde(rename = "oauthSamlAssertionCertificateChain")]
        OauthSamlAssertionCertificateChain,
        #[serde(rename = "oauthSamlAssertionPrivateKey")]
        OauthSamlAssertionPrivateKey,
        #[serde(rename = "oauthSamlAssertionThumbprint")]
        OauthSamlAssertionThumbprint,
        #[serde(rename = "oauthSamlAssertionExpiresAt")]
        OauthSamlAssertionExpiresAt,
        #[serde(rename = "oauthSamlAssertionKeySource")]
        OauthSamlAssertionKeySource,
        #[serde(rename = "oauthIssuedSoftwareStatement")]
        OauthIssuedSoftwareStatement,
        #[serde(rename = "oauthTlsClientAuthSubjectDn")]
        OauthTlsClientAuthSubjectDn,
        #[serde(rename = "oauthTlsClientAuthSanDns")]
        OauthTlsClientAuthSanDns,
        #[serde(rename = "oauthTlsClientAuthSanUri")]
        OauthTlsClientAuthSanUri,
        #[serde(rename = "oauthTlsClientAuthSanIp")]
        OauthTlsClientAuthSanIp,
        #[serde(rename = "oauthTlsClientAuthSanEmail")]
        OauthTlsClientAuthSanEmail,
        #[serde(rename = "oauthTlsClientCertificateBoundAccessTokens")]
        OauthTlsClientCertificateBoundAccessTokens,
        #[serde(rename = "oauthTlsClientCertificateThumbprint")]
        OauthTlsClientCertificateThumbprint,
        #[serde(rename = "samlSpMetadataUrl")]
        SamlSpMetadataUrl,
        #[serde(rename = "samlSpMetadata")]
        SamlSpMetadata,
        #[serde(rename = "samlEncryptionCertificate")]
        SamlEncryptionCertificate,
        #[serde(rename = "samlSpMetadataSigningCertificate")]
        SamlSpMetadataSigningCertificate,
        #[serde(rename = "saml2EncryptAssertion")]
        Saml2EncryptAssertion,
        #[serde(rename = "saml2EncryptionAlgorithm")]
        Saml2EncryptionAlgorithm,
        #[serde(rename = "saml2KeyTransportAlgorithm")]
        Saml2KeyTransportAlgorithm,
        #[serde(rename = "saml2EncryptLogoutNameId")]
        Saml2EncryptLogoutNameId,
        #[serde(rename = "oauthAccessTokenTtlS")]
        OauthAccessTokenTtlS,
        #[serde(rename = "oauthIdTokenTtlS")]
        OauthIdTokenTtlS,
        #[serde(rename = "oauthRefreshTokenTtlS")]
        OauthRefreshTokenTtlS,
        #[serde(rename = "oauthRefreshIdleSeconds")]
        OauthRefreshIdleSeconds,
        #[serde(rename = "oauthMaxAuthAgeS")]
        OauthMaxAuthAgeS,
        #[serde(rename = "oauthClaimsAccessToken")]
        OauthClaimsAccessToken,
        #[serde(rename = "oauthClaimsIdToken")]
        OauthClaimsIdToken,
        #[serde(rename = "oauthClaimsUserinfo")]
        OauthClaimsUserinfo,
        #[serde(rename = "oauthClaimAttributesAccessToken")]
        OauthClaimAttributesAccessToken,
        #[serde(rename = "oauthClaimAttributesIdToken")]
        OauthClaimAttributesIdToken,
        #[serde(rename = "oauthClaimAttributesUserinfo")]
        OauthClaimAttributesUserinfo,
        #[serde(rename = "oauthClaimsCombineAccessToken")]
        OauthClaimsCombineAccessToken,
        #[serde(rename = "oauthClaimsCombineIdToken")]
        OauthClaimsCombineIdToken,
        #[serde(rename = "oauthClaimsCombineUserinfo")]
        OauthClaimsCombineUserinfo,
        #[serde(rename = "oauthPermissionClaims")]
        OauthPermissionClaims,
        #[serde(rename = "oauthAccessTokenClaimsCombine")]
        OauthAccessTokenClaimsCombine,
        #[serde(rename = "oauthRevokeRefreshOnLogout")]
        OauthRevokeRefreshOnLogout,
        #[serde(rename = "oauthThirdPartyInitiatedLogin")]
        OauthThirdPartyInitiatedLogin,
        #[serde(rename = "oauthSpInitiatedSso")]
        OauthSpInitiatedSso,
        #[serde(rename = "oauthInitiateLoginUri")]
        OauthInitiateLoginUri,
        #[serde(rename = "oauthLogoUri")]
        OauthLogoUri,
        #[serde(rename = "oauthPolicyUri")]
        OauthPolicyUri,
        #[serde(rename = "oauthTosUri")]
        OauthTosUri,
        #[serde(rename = "oauthTokenExchangeRefreshToken")]
        OauthTokenExchangeRefreshToken,
        #[serde(rename = "appDefaultDelegationSemantics")]
        AppDefaultDelegationSemantics,
        #[serde(rename = "appNotDelegated")]
        AppNotDelegated,
        #[serde(rename = "appMayAct")]
        AppMayAct,
        #[serde(rename = "appGroupsClaim")]
        AppGroupsClaim,
        #[serde(rename = "appGroupsClaimName")]
        AppGroupsClaimName,
        #[serde(rename = "appGroupsClaimValue")]
        AppGroupsClaimValue,
        #[serde(rename = "appGroupsClaimFromMemberOf")]
        AppGroupsClaimFromMemberOf,
        #[serde(rename = "wsfedAssertionLifetimeMin")]
        WsfedAssertionLifetimeMin,
        #[serde(rename = "saml2CustomAttributes")]
        Saml2CustomAttributes,
        #[serde(rename = "saml11CustomAttributes")]
        Saml11CustomAttributes,
        #[serde(rename = "saml2ClaimAttributes")]
        Saml2ClaimAttributes,
        #[serde(rename = "saml11ClaimAttributes")]
        Saml11ClaimAttributes,
        #[serde(rename = "saml2ClaimsCombine")]
        Saml2ClaimsCombine,
        #[serde(rename = "saml11ClaimsCombine")]
        Saml11ClaimsCombine,
        #[serde(rename = "vcCredentialClaimAttributes")]
        VcCredentialClaimAttributes,
        #[serde(rename = "saml2AssertionLifetimeMin")]
        Saml2AssertionLifetimeMin,
        #[serde(rename = "saml2SignAssertion")]
        Saml2SignAssertion,
        #[serde(rename = "saml2SignResponse")]
        Saml2SignResponse,
        #[serde(rename = "saml2NameIdFormat")]
        Saml2NameIdFormat,
        #[serde(rename = "saml2ArtifactTtlS")]
        Saml2ArtifactTtlS,
        #[serde(rename = "saml11AssertionLifetimeMin")]
        Saml11AssertionLifetimeMin,
        #[serde(rename = "saml11SignAssertion")]
        Saml11SignAssertion,
        #[serde(rename = "saml11SignResponse")]
        Saml11SignResponse,
        #[serde(rename = "saml11NameIdFormat")]
        Saml11NameIdFormat,
        #[serde(rename = "saml11ArtifactTtlS")]
        Saml11ArtifactTtlS,
        #[serde(rename = "saml2IdpInitiatedSso")]
        Saml2IdpInitiatedSso,
        #[serde(rename = "saml2SpInitiatedSso")]
        Saml2SpInitiatedSso,
        #[serde(rename = "saml11IdpInitiatedSso")]
        Saml11IdpInitiatedSso,
        #[serde(rename = "saml11SpInitiatedSso")]
        Saml11SpInitiatedSso,
        #[serde(rename = "wsfedIdpInitiatedSso")]
        WsfedIdpInitiatedSso,
        #[serde(rename = "wsfedSpInitiatedSso")]
        WsfedSpInitiatedSso,
        #[serde(rename = "krb5ClaimsPac")]
        Krb5ClaimsPac,
        #[serde(rename = "gnapClaimsAccessToken")]
        GnapClaimsAccessToken,
        #[serde(rename = "krb5TrustedForDelegation")]
        Krb5TrustedForDelegation,
        #[serde(rename = "krb5ForeignTgtDelegation")]
        Krb5ForeignTgtDelegation,
        #[serde(rename = "appRegistrationAccessToken")]
        AppRegistrationAccessToken,
        #[serde(rename = "acmeDefaultProfile")]
        AcmeDefaultProfile,
        #[serde(rename = "acmeCertificateLifetimeDays")]
        AcmeCertificateLifetimeDays,
        #[serde(rename = "estDefaultProfile")]
        EstDefaultProfile,
        #[serde(rename = "estCertificateLifetimeDays")]
        EstCertificateLifetimeDays,
        #[serde(rename = "scepDefaultProfile")]
        ScepDefaultProfile,
        #[serde(rename = "scepCertificateLifetimeDays")]
        ScepCertificateLifetimeDays,
        #[serde(rename = "estBasicAuthentication")]
        EstBasicAuthentication,
        #[serde(rename = "estCertificateAuthentication")]
        EstCertificateAuthentication,
        #[serde(rename = "estServerKeyGeneration")]
        EstServerKeyGeneration,
        #[serde(rename = "enrollMaxCertificates")]
        EnrollMaxCertificates,
        #[serde(rename = "didPrivateKeys")]
        DidPrivateKeys,
        #[serde(rename = "secretDestProvider")]
        SecretDestProvider,
        #[serde(rename = "secretDestPayload")]
        SecretDestPayload,
        #[serde(rename = "secretDestRegion")]
        SecretDestRegion,
        #[serde(rename = "secretDestProject")]
        SecretDestProject,
        #[serde(rename = "secretDestEndpoint")]
        SecretDestEndpoint,
        #[serde(rename = "secretDestMount")]
        SecretDestMount,
        #[serde(rename = "secretDestField")]
        SecretDestField,
        #[serde(rename = "secretDestDirectory")]
        SecretDestDirectory,
        #[serde(rename = "secretDestCaCertificates")]
        SecretDestCaCertificates,
        #[serde(rename = "secretDestCredential")]
        SecretDestCredential,
        #[serde(rename = "scimClientBaseUrl")]
        ScimClientBaseUrl,
        #[serde(rename = "scimClientEnabled")]
        ScimClientEnabled,
        #[serde(rename = "scimClientAuthMethod")]
        ScimClientAuthMethod,
        #[serde(rename = "scimClientUsername")]
        ScimClientUsername,
        #[serde(rename = "scimClientPassword")]
        ScimClientPassword,
        #[serde(rename = "scimClientTokenEndpoint")]
        ScimClientTokenEndpoint,
        #[serde(rename = "scimClientOAuthClientId")]
        ScimClientOAuthClientId,
        #[serde(rename = "scimClientOAuthClientSecret")]
        ScimClientOAuthClientSecret,
        #[serde(rename = "scimClientOAuthClientAuth")]
        ScimClientOAuthClientAuth,
        #[serde(rename = "scimClientOAuthScope")]
        ScimClientOAuthScope,
        #[serde(rename = "scimClientOAuthResource")]
        ScimClientOAuthResource,
        #[serde(rename = "scimClientTlsSource")]
        ScimClientTlsSource,
        #[serde(rename = "scimClientTlsCertificate")]
        ScimClientTlsCertificate,
        #[serde(rename = "scimClientTlsPrivateKey")]
        ScimClientTlsPrivateKey,
        #[serde(rename = "scimClientCaCertificates")]
        ScimClientCaCertificates,
        #[serde(rename = "scimClientScopeMode")]
        ScimClientScopeMode,
        #[serde(rename = "scimClientScopeFilter")]
        ScimClientScopeFilter,
        #[serde(rename = "scimClientGroupMode")]
        ScimClientGroupMode,
        #[serde(rename = "scimClientDeprovision")]
        ScimClientDeprovision,
        #[serde(rename = "scimClientReconcileMinutes")]
        ScimClientReconcileMinutes,
        #[serde(rename = "scimClientJurisdiction")]
        ScimClientJurisdiction,
        #[serde(rename = "scimClientMaxRequestsPerSecond")]
        ScimClientMaxRequestsPerSecond,
        #[serde(rename = "ssfCaepIncludeReasons")]
        SsfCaepIncludeReasons,
        #[serde(rename = "ssfCaepReasonLanguage")]
        SsfCaepReasonLanguage,
        #[serde(rename = "ssfCaepOmitEventTimestamp")]
        SsfCaepOmitEventTimestamp,
        #[serde(rename = "ssfRiscIncludeReasons")]
        SsfRiscIncludeReasons,
        #[serde(rename = "ssfRiscReasonLanguage")]
        SsfRiscReasonLanguage,
        #[serde(rename = "ssfRiscOmitEventTimestamp")]
        SsfRiscOmitEventTimestamp,
        #[serde(rename = "ssfSigningAlgorithm")]
        SsfSigningAlgorithm,
        #[serde(rename = "ssfMinVerificationInterval")]
        SsfMinVerificationInterval,
        #[serde(rename = "ssfInactivityTimeoutS")]
        SsfInactivityTimeoutS,
        #[serde(rename = "ssfInactivityAction")]
        SsfInactivityAction,
        #[serde(rename = "ssfVerificationEveryS")]
        SsfVerificationEveryS,
        #[serde(rename = "ssfStreamStatusOnCreate")]
        SsfStreamStatusOnCreate,
        #[serde(rename = "ssfMaxStreams")]
        SsfMaxStreams,
        #[serde(rename = "ssfMaxSubjectsPerStream")]
        SsfMaxSubjectsPerStream,
        #[serde(rename = "ssfMaxQueuedEvents")]
        SsfMaxQueuedEvents,
        #[serde(rename = "ssfPollMaxEvents")]
        SsfPollMaxEvents,
        #[serde(rename = "ssfDeadLetterMaxPerStream")]
        SsfDeadLetterMaxPerStream,
        #[serde(rename = "ssfPushTimeoutMs")]
        SsfPushTimeoutMs,
        #[serde(rename = "ssfPushRetries")]
        SsfPushRetries,
        #[serde(rename = "ssfPushRetryDelayMs")]
        SsfPushRetryDelayMs,
        #[serde(rename = "gnapInstanceId")]
        GnapInstanceId,
        #[serde(rename = "gnapKey")]
        GnapKey,
        #[serde(rename = "gnapKeyReference")]
        GnapKeyReference,
        #[serde(rename = "gnapKeyProof")]
        GnapKeyProof,
        #[serde(rename = "gnapMtlsTrust")]
        GnapMtlsTrust,
        #[serde(rename = "gnapSymmetricKey")]
        GnapSymmetricKey,
        #[serde(rename = "gnapSymmetricAlg")]
        GnapSymmetricAlg,
        #[serde(rename = "gnapClassId")]
        GnapClassId,
        #[serde(rename = "gnapDisplayUri")]
        GnapDisplayUri,
        #[serde(rename = "gnapLogoUri")]
        GnapLogoUri,
        #[serde(rename = "gnapBearerTokens")]
        GnapBearerTokens,
        #[serde(rename = "gnapSkipInteraction")]
        GnapSkipInteraction,
        #[serde(rename = "gnapAccessTokenFormat")]
        GnapAccessTokenFormat,
        #[serde(rename = "gnapAccessTokenLifetimeS")]
        GnapAccessTokenLifetimeS,
        #[serde(rename = "gnapOwnerLookupUri")]
        GnapOwnerLookupUri,
        #[serde(rename = "gnapJweKey")]
        GnapJweKey,
        #[serde(rename = "gnapScopedSignals")]
        GnapScopedSignals,
        #[serde(rename = "appFederationAutoRedirect")]
        AppFederationAutoRedirect,
        #[serde(rename = "appAuthnPolicy")]
        AppAuthnPolicy,
        #[serde(rename = "appPasskeyPolicy")]
        AppPasskeyPolicy,
        #[serde(rename = "appLocalePolicy")]
        AppLocalePolicy,
        #[serde(rename = "appPasswordPolicy")]
        AppPasswordPolicy,
        #[serde(rename = "appPostLoginPolicy")]
        AppPostLoginPolicy,
        #[serde(rename = "umaOwnsResources")]
        UmaOwnsResources,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identifier, exactly as the registry holds it.
        pub application: String,
        /// One of the editable single-valued attributes. GET
        /// /admin/ldap/applications publishes the schema with an `editable` member
        /// on every row.
        pub attribute: BodyAttribute,
        /// The new value; empty clears the attribute. For the admin console, the
        /// user portal and the reports application, emptying oauthMaxAuthAgeS,
        /// oauthRefreshTokenTtlS or oauthRefreshIdleSeconds is refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// Required when this write changes oauthMaxAuthAgeS, oauthRefreshTokenTtlS
        /// or oauthRefreshIdleSeconds on the admin console, the user portal or the
        /// reports application. true, "true", "on" or "1". An unchanged value does
        /// not need it (#825).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors86;
}

/// Declare or replace an access type a resource application owns
pub mod set_application_access_type {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-access-type";
    pub const OPERATION_ID: &str = "setApplicationAccessType";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyInteraction {
        #[serde(rename = "always")]
        Always,
        #[serde(rename = "default")]
        Default,
        #[serde(rename = "never")]
        Never,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(rename = "type")]
        pub type_: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locations: Option<sts_model_base::unions::StringOrList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<sts_model_base::unions::StringOrList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub datatypes: Option<sts_model_base::unions::StringOrList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub privileges: Option<sts_model_base::unions::StringOrList>,
        #[serde(rename = "requiredMembers", default, skip_serializing_if = "Option::is_none")]
        pub required_members: Option<sts_model_base::unions::StringOrList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub interaction: Option<BodyInteraction>,
        #[serde(rename = "consentActions", default, skip_serializing_if = "Option::is_none")]
        pub consent_actions: Option<sts_model_base::unions::StringOrList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bearer: Option<sts_model_base::unions::BoolOrString>,
        #[serde(rename = "maxLifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub max_lifetime_s: Option<sts_model_base::unions::IntegerOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        #[serde(rename = "derivableFrom", default, skip_serializing_if = "Option::is_none")]
        pub derivable_from: Option<sts_model_base::unions::StringOrList>,
        #[serde(rename = "introspectionClaims", default, skip_serializing_if = "Option::is_none")]
        pub introspection_claims: Option<sts_model_base::unions::StringOrList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_base::unions::StringOrObject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<sts_model_base::unions::StringOrObject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub xacml: Option<sts_model_base::unions::StringOrList>,
        #[serde(rename = "notForPolicy", default, skip_serializing_if = "Option::is_none")]
        pub not_for_policy: Option<sts_model_base::unions::StringOrList>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors97;
}

/// Map one member of an access type to an XACML attribute
pub mod set_application_access_type_row {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-access-type-row";
    pub const OPERATION_ID: &str = "setApplicationAccessTypeRow";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(rename = "type")]
        pub type_: String,
        pub path: String,
        #[serde(rename = "attributeId")]
        pub attribute_id: String,
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
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors97;
}

/// Set an application's own directory-attribute selection for a claim set or
/// its credentials
pub mod set_application_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-claim-attributes";
    pub const OPERATION_ID: &str = "setApplicationClaimAttributes";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "userinfo")]
        Userinfo,
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "credential")]
        Credential,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub set: BodySet,
        pub attributes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors94;
}

/// Set an application's access token, ID Token and UserInfo directory-attribute
/// selections together, writing only the ones that changed
pub mod set_application_claim_selections {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-claim-selections";
    pub const OPERATION_ID: &str = "setApplicationClaimSelections";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub access_token: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id_token: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub userinfo: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors95;
}

/// Set one of an application's own custom claims or SAML attributes
pub mod set_application_custom_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-custom-claim";
    pub const OPERATION_ID: &str = "setApplicationCustomClaim";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySet {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "userinfo")]
        Userinfo,
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "kerberos-pac")]
        KerberosPac,
        #[serde(rename = "gnap_access_token")]
        GnapAccessToken,
    }

    /// The JSON type of an attribute row in the JSON sets, `gnap_access_token`
    /// among them; in `kerberos-pac` (#493) every row's PAC claim type, of string,
    /// int64, uint64 and boolean.
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
        #[serde(rename = "int64")]
        Int64,
        #[serde(rename = "uint64")]
        Uint64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub set: BodySet,
        pub name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        /// The JSON type of an attribute row in the JSON sets, `gnap_access_token`
        /// among them; in `kerberos-pac` (#493) every row's PAC claim type, of
        /// string, int64, uint64 and boolean.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
        pub name_format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub namespace: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors93;
}

/// Name the members of an access type its policy deliberately never sees
pub mod set_application_access_type_not_for_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-not-for-policy";
    pub const OPERATION_ID: &str = "setApplicationAccessTypeNotForPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(rename = "type")]
        pub type_: String,
        #[serde(rename = "notForPolicy", default, skip_serializing_if = "Option::is_none")]
        pub not_for_policy: Option<sts_model_base::unions::StringOrList>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors97;
}

/// Map claims to one of a resource server's own scopes
pub mod set_application_permission_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/set-permission-claims";
    pub const OPERATION_ID: &str = "setApplicationPermissionClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub permission: String,
        pub attributes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors96;
}

/// Sign the DID Configuration resource for one of an application's
/// LinkedDomains origins
pub mod sign_application_domain_linkage {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/sign-domain-linkage";
    pub const OPERATION_ID: &str = "signApplicationDomainLinkage";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        pub origin: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors91;
}

/// Set several attributes of an application at once
pub mod update_application_fields {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/applications/update-fields";
    pub const OPERATION_ID: &str = "updateApplicationFields";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub application: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<String>>,
        /// Set by the console's form, which draws the families as checkboxes:
        /// `protocols` is then the whole list, and none ticked means none.
        #[serde(rename = "protocolsPresent", default, skip_serializing_if = "Option::is_none")]
        pub protocols_present: Option<sts_model_base::unions::BoolOrString>,
        /// The fields the console's form drew, by attribute name, space or comma
        /// separated or as a list: each one is cleared when the form carries no
        /// value for it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<sts_model_base::unions::StringOrList>,
        /// Required when this save changes oauthMaxAuthAgeS, oauthRefreshTokenTtlS
        /// or oauthRefreshIdleSeconds on the admin console, the user portal or the
        /// reports application. true, "true", "on" or "1". An unchanged value does
        /// not need it. Without it the whole save is refused and nothing is written
        /// (#825).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors86;
}

/// What happened here, in order, filtered and paged
pub mod get_audit {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/audit";
    pub const OPERATION_ID: &str = "getAudit";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryCategory {
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
        #[serde(rename = "mail")]
        Mail,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryAction {
        #[serde(rename = "authentication")]
        Authentication,
        #[serde(rename = "authentication.refused")]
        AuthenticationRefused,
        #[serde(rename = "portal.activate")]
        PortalActivate,
        #[serde(rename = "portal.activate.refused")]
        PortalActivateRefused,
        #[serde(rename = "portal.password.changed")]
        PortalPasswordChanged,
        #[serde(rename = "authn.password.changed")]
        AuthnPasswordChanged,
        #[serde(rename = "portal.password.refused")]
        PortalPasswordRefused,
        #[serde(rename = "portal.password.csrf")]
        PortalPasswordCsrf,
        #[serde(rename = "portal.signout")]
        PortalSignout,
        #[serde(rename = "portal.signout.csrf")]
        PortalSignoutCsrf,
        #[serde(rename = "portal.key.enrolled")]
        PortalKeyEnrolled,
        #[serde(rename = "portal.key.removed")]
        PortalKeyRemoved,
        #[serde(rename = "portal.key.renamed")]
        PortalKeyRenamed,
        #[serde(rename = "portal.tls-client.issued")]
        PortalTlsClientIssued,
        #[serde(rename = "portal.tls-client.revoked")]
        PortalTlsClientRevoked,
        #[serde(rename = "activation.issued")]
        ActivationIssued,
        #[serde(rename = "portal.password-reset")]
        PortalPasswordReset,
        #[serde(rename = "portal.password-reset.refused")]
        PortalPasswordResetRefused,
        #[serde(rename = "authn.mfa.enrolment.required")]
        AuthnMfaEnrolmentRequired,
        #[serde(rename = "authn.mfa.enrolment.started")]
        AuthnMfaEnrolmentStarted,
        #[serde(rename = "authn.mfa.enrolment.offered")]
        AuthnMfaEnrolmentOffered,
        #[serde(rename = "authn.mfa.enrolment.declined")]
        AuthnMfaEnrolmentDeclined,
        #[serde(rename = "authn.second-factor.skipped")]
        AuthnSecondFactorSkipped,
        #[serde(rename = "authn.mfa.enrolment.at-risk")]
        AuthnMfaEnrolmentAtRisk,
        #[serde(rename = "authn.mfa.enrolled")]
        AuthnMfaEnrolled,
        #[serde(rename = "authn.recovery.refused")]
        AuthnRecoveryRefused,
        #[serde(rename = "authn.recovery.limited")]
        AuthnRecoveryLimited,
        #[serde(rename = "authn.recovery.completed")]
        AuthnRecoveryCompleted,
        #[serde(rename = "authn.sign-in.started-over")]
        AuthnSignInStartedOver,
        #[serde(rename = "portal.mfa.started")]
        PortalMfaStarted,
        #[serde(rename = "portal.mfa.enrolled")]
        PortalMfaEnrolled,
        #[serde(rename = "portal.mfa.refused")]
        PortalMfaRefused,
        #[serde(rename = "portal.mfa.removed")]
        PortalMfaRemoved,
        #[serde(rename = "portal.mfa.csrf")]
        PortalMfaCsrf,
        #[serde(rename = "portal.activate.mfa.started")]
        PortalActivateMfaStarted,
        #[serde(rename = "portal.activate.mfa.refused")]
        PortalActivateMfaRefused,
        #[serde(rename = "portal.activate.key.started")]
        PortalActivateKeyStarted,
        #[serde(rename = "portal.activate.key.enrolled")]
        PortalActivateKeyEnrolled,
        #[serde(rename = "portal.activate.key.refused")]
        PortalActivateKeyRefused,
        #[serde(rename = "session.start")]
        SessionStart,
        #[serde(rename = "session.end")]
        SessionEnd,
        #[serde(rename = "session.renew")]
        SessionRenew,
        #[serde(rename = "authn.session.bound")]
        AuthnSessionBound,
        #[serde(rename = "authn.session.refreshed")]
        AuthnSessionRefreshed,
        #[serde(rename = "authn.session.binding-skipped")]
        AuthnSessionBindingSkipped,
        #[serde(rename = "logout.global")]
        LogoutGlobal,
        #[serde(rename = "logout.selective")]
        LogoutSelective,
        #[serde(rename = "logout.backchannel")]
        LogoutBackchannel,
        #[serde(rename = "mail.queued")]
        MailQueued,
        #[serde(rename = "mail.sent")]
        MailSent,
        #[serde(rename = "mail.dead")]
        MailDead,
        #[serde(rename = "mail.refused")]
        MailRefused,
        #[serde(rename = "mail.reset-requested")]
        MailResetRequested,
        #[serde(rename = "mail.retry")]
        MailRetry,
        #[serde(rename = "mail.template")]
        MailTemplate,
        #[serde(rename = "branding.logo")]
        BrandingLogo,
        #[serde(rename = "mail.verified")]
        MailVerified,
        #[serde(rename = "mail.preferences")]
        MailPreferences,
        #[serde(rename = "scheduler.run")]
        SchedulerRun,
        #[serde(rename = "scheduler.step-down")]
        SchedulerStepDown,
        #[serde(rename = "keys.rotate")]
        KeysRotate,
        #[serde(rename = "keys.rotate.emergency")]
        KeysRotateEmergency,
        #[serde(rename = "application.secret-expiring")]
        ApplicationSecretExpiring,
        #[serde(rename = "application.secret-expired")]
        ApplicationSecretExpired,
        #[serde(rename = "keys.retire")]
        KeysRetire,
        #[serde(rename = "keys.data-key-rotate")]
        KeysDataKeyRotate,
        #[serde(rename = "keys.data-key-reencrypt")]
        KeysDataKeyReencrypt,
        #[serde(rename = "keys.data-key-destroy")]
        KeysDataKeyDestroy,
        #[serde(rename = "keys.kek-rotate")]
        KeysKekRotate,
        #[serde(rename = "keys.pin")]
        KeysPin,
        #[serde(rename = "keys.unpin")]
        KeysUnpin,
        #[serde(rename = "oidfed.key-minted")]
        OidfedKeyMinted,
        #[serde(rename = "oidfed.key-rotated")]
        OidfedKeyRotated,
        #[serde(rename = "oidfed.key-revoked")]
        OidfedKeyRevoked,
        #[serde(rename = "oidfed.subordinate-set")]
        OidfedSubordinateSet,
        #[serde(rename = "oidfed.subordinate-removed")]
        OidfedSubordinateRemoved,
        #[serde(rename = "oidfed.anchor-set")]
        OidfedAnchorSet,
        #[serde(rename = "oidfed.anchor-removed")]
        OidfedAnchorRemoved,
        #[serde(rename = "oidfed.mark-type-set")]
        OidfedMarkTypeSet,
        #[serde(rename = "oidfed.remove-mark-type")]
        OidfedRemoveMarkType,
        #[serde(rename = "oidfed.mark-policy-set")]
        OidfedMarkPolicySet,
        #[serde(rename = "oidfed.remove-mark-policy")]
        OidfedRemoveMarkPolicy,
        #[serde(rename = "oidfed.mark-issued")]
        OidfedMarkIssued,
        #[serde(rename = "oidfed.mark-revoked")]
        OidfedMarkRevoked,
        #[serde(rename = "oidfed.held-mark-added")]
        OidfedHeldMarkAdded,
        #[serde(rename = "oidfed.held-mark-removed")]
        OidfedHeldMarkRemoved,
        #[serde(rename = "oidfed.act-refused")]
        OidfedActRefused,
        #[serde(rename = "oidfed.resolved")]
        OidfedResolved,
        #[serde(rename = "device.create")]
        DeviceCreate,
        #[serde(rename = "device.browser.remembered")]
        DeviceBrowserRemembered,
        #[serde(rename = "device.update")]
        DeviceUpdate,
        #[serde(rename = "device.delete")]
        DeviceDelete,
        #[serde(rename = "device.evict")]
        DeviceEvict,
        #[serde(rename = "device.attestation-revoked")]
        DeviceAttestationRevoked,
        #[serde(rename = "webauthn.ceremony")]
        WebauthnCeremony,
        #[serde(rename = "webauthn.algorithm-mismatch")]
        WebauthnAlgorithmMismatch,
        #[serde(rename = "webauthn.client.learned")]
        WebauthnClientLearned,
        #[serde(rename = "webauthn.attestation-revoked")]
        WebauthnAttestationRevoked,
        #[serde(rename = "device.key-add")]
        DeviceKeyAdd,
        #[serde(rename = "device.key-remove")]
        DeviceKeyRemove,
        #[serde(rename = "device.compliance")]
        DeviceCompliance,
        #[serde(rename = "device.enrol.refused")]
        DeviceEnrolRefused,
        #[serde(rename = "user.create")]
        UserCreate,
        #[serde(rename = "user.delete")]
        UserDelete,
        #[serde(rename = "user.update")]
        UserUpdate,
        #[serde(rename = "user.rename")]
        UserRename,
        #[serde(rename = "user.export")]
        UserExport,
        #[serde(rename = "user.import")]
        UserImport,
        #[serde(rename = "cells.rehome")]
        CellsRehome,
        #[serde(rename = "user.query")]
        UserQuery,
        #[serde(rename = "group.create")]
        GroupCreate,
        #[serde(rename = "group.delete")]
        GroupDelete,
        #[serde(rename = "group.update")]
        GroupUpdate,
        #[serde(rename = "group.rename")]
        GroupRename,
        #[serde(rename = "entry.create")]
        EntryCreate,
        #[serde(rename = "entry.delete")]
        EntryDelete,
        #[serde(rename = "entry.update")]
        EntryUpdate,
        #[serde(rename = "entry.rename")]
        EntryRename,
        #[serde(rename = "directory.search")]
        DirectorySearch,
        #[serde(rename = "directory.compare")]
        DirectoryCompare,
        #[serde(rename = "directory.bind")]
        DirectoryBind,
        #[serde(rename = "application.create")]
        ApplicationCreate,
        #[serde(rename = "application.secret-revealed")]
        ApplicationSecretRevealed,
        #[serde(rename = "application.export")]
        ApplicationExport,
        #[serde(rename = "application.import")]
        ApplicationImport,
        #[serde(rename = "application.add-owner")]
        ApplicationAddOwner,
        #[serde(rename = "application.remove-owner")]
        ApplicationRemoveOwner,
        #[serde(rename = "application.update")]
        ApplicationUpdate,
        #[serde(rename = "consent.grant")]
        ConsentGrant,
        #[serde(rename = "consent.deny")]
        ConsentDeny,
        #[serde(rename = "consent.revoke")]
        ConsentRevoke,
        #[serde(rename = "application.delete")]
        ApplicationDelete,
        #[serde(rename = "oidfed.registered")]
        OidfedRegistered,
        #[serde(rename = "oidfed.registration-refused")]
        OidfedRegistrationRefused,
        #[serde(rename = "admin.view")]
        AdminView,
        #[serde(rename = "admin.change")]
        AdminChange,
        #[serde(rename = "admin.config-dump")]
        AdminConfigDump,
        #[serde(rename = "claims.change")]
        ClaimsChange,
        #[serde(rename = "admin.role.change")]
        AdminRoleChange,
        #[serde(rename = "admin.console.bootstrap")]
        AdminConsoleBootstrap,
        #[serde(rename = "admin.mail.set")]
        AdminMailSet,
        #[serde(rename = "admin.pseudonym.set")]
        AdminPseudonymSet,
        #[serde(rename = "admin.mfa.totp.cleared")]
        AdminMfaTotpCleared,
        #[serde(rename = "admin.mfa.key.cleared")]
        AdminMfaKeyCleared,
        #[serde(rename = "admin.mfa.key.renamed")]
        AdminMfaKeyRenamed,
        #[serde(rename = "admin.password.reset")]
        AdminPasswordReset,
        #[serde(rename = "admin.password.reset-link")]
        AdminPasswordResetLink,
        #[serde(rename = "admin.mfa.primary-keys.removed")]
        AdminMfaPrimaryKeysRemoved,
        #[serde(rename = "admin.mfa.disabled")]
        AdminMfaDisabled,
        #[serde(rename = "admin.mfa.required")]
        AdminMfaRequired,
        #[serde(rename = "admin.mfa.unrequired")]
        AdminMfaUnrequired,
        #[serde(rename = "admin.delegation.not-delegated")]
        AdminDelegationNotDelegated,
        #[serde(rename = "admin.delegation.may-act")]
        AdminDelegationMayAct,
        #[serde(rename = "admin.delegation.semantics")]
        AdminDelegationSemantics,
        #[serde(rename = "portal.delegation.may-act")]
        PortalDelegationMayAct,
        #[serde(rename = "portal.delegation.search")]
        PortalDelegationSearch,
        #[serde(rename = "admin.password-policy.change")]
        AdminPasswordPolicyChange,
        #[serde(rename = "admin.policies.export")]
        AdminPoliciesExport,
        #[serde(rename = "admin.policies.import")]
        AdminPoliciesImport,
        #[serde(rename = "admin.policies.trust-signer")]
        AdminPoliciesTrustSigner,
        #[serde(rename = "admin.authn-policy.change")]
        AdminAuthnPolicyChange,
        #[serde(rename = "admin.locale-policy.change")]
        AdminLocalePolicyChange,
        #[serde(rename = "admin.post-login-policy.change")]
        AdminPostLoginPolicyChange,
        #[serde(rename = "authn.post-login.asked")]
        AuthnPostLoginAsked,
        #[serde(rename = "authn.post-login.skipped")]
        AuthnPostLoginSkipped,
        #[serde(rename = "authn.post-login.done")]
        AuthnPostLoginDone,
        #[serde(rename = "authn.post-login.held")]
        AuthnPostLoginHeld,
        #[serde(rename = "admin.post-login-activity.change")]
        AdminPostLoginActivityChange,
        #[serde(rename = "authn.post-login.activity-run")]
        AuthnPostLoginActivityRun,
        #[serde(rename = "authn.post-login.unsupported")]
        AuthnPostLoginUnsupported,
        #[serde(rename = "webauthn.key.possibly-replaced")]
        WebauthnKeyPossiblyReplaced,
        #[serde(rename = "authn.mail-factor.change")]
        AuthnMailFactorChange,
        #[serde(rename = "authn.mail-factor.sent")]
        AuthnMailFactorSent,
        #[serde(rename = "authn.mail-factor.accepted")]
        AuthnMailFactorAccepted,
        #[serde(rename = "authn.mail-factor.refused")]
        AuthnMailFactorRefused,
        #[serde(rename = "admin.truststore.change")]
        AdminTruststoreChange,
        #[serde(rename = "admin.pki.trust.change")]
        AdminPkiTrustChange,
        #[serde(rename = "krb5.keys.derived")]
        Krb5KeysDerived,
        #[serde(rename = "krb5.trust.sid-filtered")]
        Krb5TrustSidFiltered,
        #[serde(rename = "admin.krb5.keys.cleared")]
        AdminKrb5KeysCleared,
        #[serde(rename = "admin.krb5.service.created")]
        AdminKrb5ServiceCreated,
        #[serde(rename = "admin.krb5.service.rotated")]
        AdminKrb5ServiceRotated,
        #[serde(rename = "admin.krb5.service.deleted")]
        AdminKrb5ServiceDeleted,
        #[serde(rename = "admin.krb5.previous.dropped")]
        AdminKrb5PreviousDropped,
        #[serde(rename = "api.read")]
        ApiRead,
        #[serde(rename = "api.change")]
        ApiChange,
        #[serde(rename = "protocol.call")]
        ProtocolCall,
        #[serde(rename = "oauth.token.revoke")]
        OauthTokenRevoke,
        #[serde(rename = "protocol.failure")]
        ProtocolFailure,
        #[serde(rename = "service.failure")]
        ServiceFailure,
        #[serde(rename = "spiffe.svid.issue")]
        SpiffeSvidIssue,
        #[serde(rename = "spiffe.svid.validate")]
        SpiffeSvidValidate,
        #[serde(rename = "spiffe.entry.create")]
        SpiffeEntryCreate,
        #[serde(rename = "spiffe.entry.update")]
        SpiffeEntryUpdate,
        #[serde(rename = "spiffe.entry.delete")]
        SpiffeEntryDelete,
        #[serde(rename = "spiffe.agent.create")]
        SpiffeAgentCreate,
        #[serde(rename = "spiffe.agent.attest")]
        SpiffeAgentAttest,
        #[serde(rename = "spiffe.agent.ban")]
        SpiffeAgentBan,
        #[serde(rename = "spiffe.agent.unban")]
        SpiffeAgentUnban,
        #[serde(rename = "spiffe.agent.delete")]
        SpiffeAgentDelete,
        #[serde(rename = "spiffe.bundle.read")]
        SpiffeBundleRead,
        #[serde(rename = "spiffe.bundle.change")]
        SpiffeBundleChange,
        #[serde(rename = "spiffe.call.refuse")]
        SpiffeCallRefuse,
        #[serde(rename = "xacml.decision")]
        XacmlDecision,
        #[serde(rename = "xacml.enforcement")]
        XacmlEnforcement,
        #[serde(rename = "authzen.decision")]
        AuthzenDecision,
        #[serde(rename = "authzen.search")]
        AuthzenSearch,
        #[serde(rename = "fga.decision")]
        FgaDecision,
        #[serde(rename = "admin.authzen.attribute.set")]
        AdminAuthzenAttributeSet,
        #[serde(rename = "admin.authzen.attribute.removed")]
        AdminAuthzenAttributeRemoved,
        #[serde(rename = "admin.authzen.scope.set")]
        AdminAuthzenScopeSet,
        #[serde(rename = "admin.authzen.pep.granted")]
        AdminAuthzenPepGranted,
        #[serde(rename = "admin.authzen.callbacks.set")]
        AdminAuthzenCallbacksSet,
        #[serde(rename = "authzen.access-request.submitted")]
        AuthzenAccessRequestSubmitted,
        #[serde(rename = "authzen.access-request.approved")]
        AuthzenAccessRequestApproved,
        #[serde(rename = "authzen.access-request.denied")]
        AuthzenAccessRequestDenied,
        #[serde(rename = "authzen.access-request.expired")]
        AuthzenAccessRequestExpired,
        #[serde(rename = "authzen.access-request.cancelled")]
        AuthzenAccessRequestCancelled,
        #[serde(rename = "authzen.access-request.revoked")]
        AuthzenAccessRequestRevoked,
        #[serde(rename = "authzen.access-request.approver-refused")]
        AuthzenAccessRequestApproverRefused,
        #[serde(rename = "authzen.access-request.callback")]
        AuthzenAccessRequestCallback,
        #[serde(rename = "xacml.issuance.refused")]
        XacmlIssuanceRefused,
        #[serde(rename = "xacml.access.refused")]
        XacmlAccessRefused,
        #[serde(rename = "xacml.issuance.alarm")]
        XacmlIssuanceAlarm,
        #[serde(rename = "xacml.pep.register")]
        XacmlPepRegister,
        #[serde(rename = "xacml.pep.certificate")]
        XacmlPepCertificate,
        #[serde(rename = "xacml.pip.query")]
        XacmlPipQuery,
        #[serde(rename = "saml2.request.signature")]
        Saml2RequestSignature,
        #[serde(rename = "gnap.grant.request")]
        GnapGrantRequest,
        #[serde(rename = "gnap.grant.consent")]
        GnapGrantConsent,
        #[serde(rename = "gnap.grant.deny")]
        GnapGrantDeny,
        #[serde(rename = "gnap.grant.approve")]
        GnapGrantApprove,
        #[serde(rename = "gnap.grant.revoke")]
        GnapGrantRevoke,
        #[serde(rename = "gnap.grant.owner-queued")]
        GnapGrantOwnerQueued,
        #[serde(rename = "gnap.grant.forward")]
        GnapGrantForward,
        #[serde(rename = "uma.resource.register")]
        UmaResourceRegister,
        #[serde(rename = "uma.resource.update")]
        UmaResourceUpdate,
        #[serde(rename = "uma.resource.delete")]
        UmaResourceDelete,
        #[serde(rename = "uma.permission.ticket")]
        UmaPermissionTicket,
        #[serde(rename = "uma.decision")]
        UmaDecision,
        #[serde(rename = "uma.grant")]
        UmaGrant,
        #[serde(rename = "uma.pct.revoke")]
        UmaPctRevoke,
        #[serde(rename = "uma.approval.request")]
        UmaApprovalRequest,
        #[serde(rename = "uma.approval.answer")]
        UmaApprovalAnswer,
        #[serde(rename = "uma.claims.gathered")]
        UmaClaimsGathered,
        #[serde(rename = "uma.share.add")]
        UmaShareAdd,
        #[serde(rename = "uma.share.remove")]
        UmaShareRemove,
        #[serde(rename = "uma.policy.alfa")]
        UmaPolicyAlfa,
        #[serde(rename = "uma.resource-server.enable")]
        UmaResourceServerEnable,
        #[serde(rename = "uma.resource-server.disable")]
        UmaResourceServerDisable,
        #[serde(rename = "uma.owns-resources.set")]
        UmaOwnsResourcesSet,
        #[serde(rename = "uma.rpt.revoke")]
        UmaRptRevoke,
        #[serde(rename = "gnap.grant.finalize")]
        GnapGrantFinalize,
        #[serde(rename = "gnap.token.issue")]
        GnapTokenIssue,
        #[serde(rename = "gnap.token.rotate")]
        GnapTokenRotate,
        #[serde(rename = "gnap.token.revoke")]
        GnapTokenRevoke,
        #[serde(rename = "gnap.rs.introspect")]
        GnapRsIntrospect,
        #[serde(rename = "gnap.rs.register")]
        GnapRsRegister,
        #[serde(rename = "ssf.stream.create")]
        SsfStreamCreate,
        #[serde(rename = "ssf.stream.update")]
        SsfStreamUpdate,
        #[serde(rename = "ssf.stream.delete")]
        SsfStreamDelete,
        #[serde(rename = "ssf.stream.status")]
        SsfStreamStatus,
        #[serde(rename = "ssf.subject.change")]
        SsfSubjectChange,
        #[serde(rename = "ssf.event.transmit")]
        SsfEventTransmit,
        #[serde(rename = "ssf.announcement.broadcast")]
        SsfAnnouncementBroadcast,
        #[serde(rename = "ssf.event.refused")]
        SsfEventRefused,
        #[serde(rename = "ssf.stream.dead")]
        SsfStreamDead,
        #[serde(rename = "ssf.stream.revived")]
        SsfStreamRevived,
        #[serde(rename = "ssf.stream.delivery")]
        SsfStreamDelivery,
        #[serde(rename = "ssf.deadletter.clear")]
        SsfDeadletterClear,
        #[serde(rename = "ssf.event.receive")]
        SsfEventReceive,
        #[serde(rename = "caep.event.auto")]
        CaepEventAuto,
        #[serde(rename = "caep.event.emit")]
        CaepEventEmit,
        #[serde(rename = "caep.session.reset")]
        CaepSessionReset,
        #[serde(rename = "caep.session.clear")]
        CaepSessionClear,
        #[serde(rename = "risc.event.auto")]
        RiscEventAuto,
        #[serde(rename = "risc.event.emit")]
        RiscEventEmit,
        #[serde(rename = "risc.account.reset")]
        RiscAccountReset,
        #[serde(rename = "risc.account.clear")]
        RiscAccountClear,
        #[serde(rename = "persistence.minted-drop")]
        PersistenceMintedDrop,
        #[serde(rename = "admin.aud-sub.set")]
        AdminAudSubSet,
        #[serde(rename = "admin.mfa.backup-codes.cleared")]
        AdminMfaBackupCodesCleared,
        #[serde(rename = "admin.password.reset-keytab")]
        AdminPasswordResetKeytab,
        #[serde(rename = "admin.user.attribute")]
        AdminUserAttribute,
        #[serde(rename = "admin.service-account.set")]
        AdminServiceAccountSet,
        #[serde(rename = "admin.service-account.cleared")]
        AdminServiceAccountCleared,
        #[serde(rename = "admin.service-account.owner-added")]
        AdminServiceAccountOwnerAdded,
        #[serde(rename = "admin.service-account.owner-removed")]
        AdminServiceAccountOwnerRemoved,
        #[serde(rename = "admin.service-account.destination-set")]
        AdminServiceAccountDestinationSet,
        #[serde(rename = "admin.service-account.rotate")]
        AdminServiceAccountRotate,
        #[serde(rename = "admin.app-password.created")]
        AdminAppPasswordCreated,
        #[serde(rename = "admin.app-password.revoked")]
        AdminAppPasswordRevoked,
        #[serde(rename = "admin.ciba.answered")]
        AdminCibaAnswered,
        #[serde(rename = "admin.device.removed")]
        AdminDeviceRemoved,
        #[serde(rename = "admin.ida.recorded")]
        AdminIdaRecorded,
        #[serde(rename = "admin.ida.removed")]
        AdminIdaRemoved,
        #[serde(rename = "admin.siop.enrolled")]
        AdminSiopEnrolled,
        #[serde(rename = "admin.siop.removed")]
        AdminSiopRemoved,
        #[serde(rename = "admin.siop.preferred")]
        AdminSiopPreferred,
        #[serde(rename = "admin.passkey.enrolment-started")]
        AdminPasskeyEnrolmentStarted,
        #[serde(rename = "admin.passkey.enrolment-refused")]
        AdminPasskeyEnrolmentRefused,
        #[serde(rename = "admin.passkey.enrolled")]
        AdminPasskeyEnrolled,
        #[serde(rename = "admin.passkey.upgrade-started")]
        AdminPasskeyUpgradeStarted,
        #[serde(rename = "admin.passkey.upgrade-refused")]
        AdminPasskeyUpgradeRefused,
        #[serde(rename = "admin.passkey.upgrade-proved")]
        AdminPasskeyUpgradeProved,
        #[serde(rename = "admin.passkey.upgrade-cancelled")]
        AdminPasskeyUpgradeCancelled,
        #[serde(rename = "admin.passkey.upgraded")]
        AdminPasskeyUpgraded,
        #[serde(rename = "ssf.signals.discover")]
        SsfSignalsDiscover,
        #[serde(rename = "ssf.signals.stream")]
        SsfSignalsStream,
        #[serde(rename = "ssf.signals.unblock")]
        SsfSignalsUnblock,
        #[serde(rename = "ssf.signals.read-stream")]
        SsfSignalsReadStream,
        #[serde(rename = "ssf.signals.update-stream")]
        SsfSignalsUpdateStream,
        #[serde(rename = "ssf.signals.delete-stream")]
        SsfSignalsDeleteStream,
        #[serde(rename = "ssf.signals.set-status")]
        SsfSignalsSetStatus,
        #[serde(rename = "ssf.signals.add-subject")]
        SsfSignalsAddSubject,
        #[serde(rename = "ssf.signals.remove-subject")]
        SsfSignalsRemoveSubject,
        #[serde(rename = "ssf.signals.verify")]
        SsfSignalsVerify,
        #[serde(rename = "application.key-issued")]
        ApplicationKeyIssued,
        #[serde(rename = "enrollment.acme.account.create")]
        EnrollmentAcmeAccountCreate,
        #[serde(rename = "enrollment.acme.account.deactivate")]
        EnrollmentAcmeAccountDeactivate,
        #[serde(rename = "enrollment.acme.account.key-change")]
        EnrollmentAcmeAccountKeyChange,
        #[serde(rename = "enrollment.eab.create")]
        EnrollmentEabCreate,
        #[serde(rename = "enrollment.eab.delete")]
        EnrollmentEabDelete,
        #[serde(rename = "enrollment.challenge.create")]
        EnrollmentChallengeCreate,
        #[serde(rename = "enrollment.challenge.delete")]
        EnrollmentChallengeDelete,
        #[serde(rename = "enrollment.issue")]
        EnrollmentIssue,
        #[serde(rename = "enrollment.issue.refused")]
        EnrollmentIssueRefused,
        #[serde(rename = "enrollment.revoke")]
        EnrollmentRevoke,
        #[serde(rename = "federation.signal-block")]
        FederationSignalBlock,
        #[serde(rename = "federation.signal-unblock")]
        FederationSignalUnblock,
        #[serde(rename = "federation.signout")]
        FederationSignout,
        #[serde(rename = "federation.signout-answered")]
        FederationSignoutAnswered,
        #[serde(rename = "federation.unlink")]
        FederationUnlink,
        #[serde(rename = "federation.connected")]
        FederationConnected,
        #[serde(rename = "federation.provider-notification")]
        FederationProviderNotification,
        #[serde(rename = "federation.group-ignored")]
        FederationGroupIgnored,
        #[serde(rename = "group.add-member")]
        GroupAddMember,
        #[serde(rename = "group.add-owner")]
        GroupAddOwner,
        #[serde(rename = "group.remove-owner")]
        GroupRemoveOwner,
        #[serde(rename = "group.owner-protected")]
        GroupOwnerProtected,
        #[serde(rename = "group.set-mail")]
        GroupSetMail,
        #[serde(rename = "group.set-policy")]
        GroupSetPolicy,
        #[serde(rename = "krb5.keytab.person")]
        Krb5KeytabPerson,
        #[serde(rename = "logout.backchannel.retry")]
        LogoutBackchannelRetry,
        #[serde(rename = "oauth.device-secret.revoke")]
        OauthDeviceSecretRevoke,
        #[serde(rename = "oauth2.ciba.notify")]
        Oauth2CibaNotify,
        #[serde(rename = "oauth2.claim-source-linked")]
        Oauth2ClaimSourceLinked,
        #[serde(rename = "oauth2.claim-source-link-refused")]
        Oauth2ClaimSourceLinkRefused,
        #[serde(rename = "oauth2.claims-providers.add-provider")]
        Oauth2ClaimsProvidersAddProvider,
        #[serde(rename = "oauth2.claims-providers.update-provider")]
        Oauth2ClaimsProvidersUpdateProvider,
        #[serde(rename = "oauth2.claims-providers.remove-provider")]
        Oauth2ClaimsProvidersRemoveProvider,
        #[serde(rename = "oauth2.claims-providers.revoke-link")]
        Oauth2ClaimsProvidersRevokeLink,
        #[serde(rename = "oauth2.command")]
        Oauth2Command,
        #[serde(rename = "oauth2.command.tenant")]
        Oauth2CommandTenant,
        #[serde(rename = "oauth2.grant-revoked")]
        Oauth2GrantRevoked,
        #[serde(rename = "oauth2.par.withdraw")]
        Oauth2ParWithdraw,
        #[serde(rename = "password.set")]
        PasswordSet,
        #[serde(rename = "service-account.rotated")]
        ServiceAccountRotated,
        #[serde(rename = "service-account.rotation-failed")]
        ServiceAccountRotationFailed,
        #[serde(rename = "portal.app-password.created")]
        PortalAppPasswordCreated,
        #[serde(rename = "portal.app-password.revoked")]
        PortalAppPasswordRevoked,
        #[serde(rename = "portal.app-password.csrf")]
        PortalAppPasswordCsrf,
        #[serde(rename = "portal.certificates.csrf")]
        PortalCertificatesCsrf,
        #[serde(rename = "portal.device.remove")]
        PortalDeviceRemove,
        #[serde(rename = "portal.device.remember-browser")]
        PortalDeviceRememberBrowser,
        #[serde(rename = "portal.kerberos.keytab")]
        PortalKerberosKeytab,
        #[serde(rename = "portal.kerberos.refused")]
        PortalKerberosRefused,
        #[serde(rename = "portal.kerberos.csrf")]
        PortalKerberosCsrf,
        #[serde(rename = "portal.key.started")]
        PortalKeyStarted,
        #[serde(rename = "portal.key.refused")]
        PortalKeyRefused,
        #[serde(rename = "portal.key.upgrade-started")]
        PortalKeyUpgradeStarted,
        #[serde(rename = "portal.key.upgrade-refused")]
        PortalKeyUpgradeRefused,
        #[serde(rename = "portal.key.upgraded")]
        PortalKeyUpgraded,
        #[serde(rename = "portal.mfa.backup-codes.generated")]
        PortalMfaBackupCodesGenerated,
        #[serde(rename = "portal.mfa.backup-codes.confirmed")]
        PortalMfaBackupCodesConfirmed,
        #[serde(rename = "portal.mfa.backup-codes.discarded")]
        PortalMfaBackupCodesDiscarded,
        #[serde(rename = "portal.risc.optOutInitiated")]
        PortalRiscOptOutInitiated,
        #[serde(rename = "portal.risc.optOutCancelled")]
        PortalRiscOptOutCancelled,
        #[serde(rename = "portal.risc.optIn")]
        PortalRiscOptIn,
        #[serde(rename = "portal.signing-key.issued")]
        PortalSigningKeyIssued,
        #[serde(rename = "portal.signing-key.removed")]
        PortalSigningKeyRemoved,
        #[serde(rename = "portal.signing-key.csrf")]
        PortalSigningKeyCsrf,
        #[serde(rename = "portal.signing-key.revoked")]
        PortalSigningKeyRevoked,
        #[serde(rename = "did.person.published")]
        DidPersonPublished,
        #[serde(rename = "did.person.version")]
        DidPersonVersion,
        #[serde(rename = "did.person.authorized")]
        DidPersonAuthorized,
        #[serde(rename = "did.person.deactivated")]
        DidPersonDeactivated,
        #[serde(rename = "admin.did.deactivated")]
        AdminDidDeactivated,
        #[serde(rename = "portal.siop.enrol")]
        PortalSiopEnrol,
        #[serde(rename = "portal.siop.remove")]
        PortalSiopRemove,
        #[serde(rename = "portal.siop.prefer")]
        PortalSiopPrefer,
        #[serde(rename = "portal.siop.view")]
        PortalSiopView,
        #[serde(rename = "portal.siop.did")]
        PortalSiopDid,
        #[serde(rename = "siop.key.pinned")]
        SiopKeyPinned,
        #[serde(rename = "siop.key.refused")]
        SiopKeyRefused,
        #[serde(rename = "portal.vc.offer")]
        PortalVcOffer,
        #[serde(rename = "portal.vc.remove")]
        PortalVcRemove,
        #[serde(rename = "risk.feedback")]
        RiskFeedback,
        #[serde(rename = "risk.response")]
        RiskResponse,
        #[serde(rename = "risk.terms.accept")]
        RiskTermsAccept,
        #[serde(rename = "attribute-sources.add")]
        AttributeSourcesAdd,
        #[serde(rename = "attribute-sources.update")]
        AttributeSourcesUpdate,
        #[serde(rename = "attribute-sources.remove")]
        AttributeSourcesRemove,
        #[serde(rename = "attribute-sources.refresh")]
        AttributeSourcesRefresh,
        #[serde(rename = "scim-client.change")]
        ScimClientChange,
        #[serde(rename = "scim-client.delivery")]
        ScimClientDelivery,
        #[serde(rename = "scim-client.reconcile")]
        ScimClientReconcile,
        #[serde(rename = "scim-client.queue")]
        ScimClientQueue,
        #[serde(rename = "secret-destination.push")]
        SecretDestinationPush,
        #[serde(rename = "secret-destination.test-push")]
        SecretDestinationTestPush,
        #[serde(rename = "roles.add-owner")]
        RolesAddOwner,
        #[serde(rename = "roles.remove-owner")]
        RolesRemoveOwner,
        #[serde(rename = "roles.confer")]
        RolesConfer,
        #[serde(rename = "roles.unconfer")]
        RolesUnconfer,
        #[serde(rename = "roles.create")]
        RolesCreate,
        #[serde(rename = "roles.delete")]
        RolesDelete,
        #[serde(rename = "roles.describe")]
        RolesDescribe,
        #[serde(rename = "node-health.collect-garbage")]
        NodeHealthCollectGarbage,
        #[serde(rename = "saml2.authnrequest")]
        Saml2Authnrequest,
        #[serde(rename = "saml2.artifact.resolve")]
        Saml2ArtifactResolve,
        #[serde(rename = "saml2.attribute-query")]
        Saml2AttributeQuery,
        #[serde(rename = "saml2.metadata.mdq")]
        Saml2MetadataMdq,
        #[serde(rename = "saml2.metadata.refresh")]
        Saml2MetadataRefresh,
        #[serde(rename = "account.add")]
        AccountAdd,
        #[serde(rename = "account.select")]
        AccountSelect,
        #[serde(rename = "account.switch")]
        AccountSwitch,
        #[serde(rename = "account.forget")]
        AccountForget,
        #[serde(rename = "account.ambiguous")]
        AccountAmbiguous,
        #[serde(rename = "session.reauthenticate")]
        SessionReauthenticate,
        #[serde(rename = "session.presented")]
        SessionPresented,
        #[serde(rename = "session.refuse")]
        SessionRefuse,
        #[serde(rename = "session.refused")]
        SessionRefused,
        #[serde(rename = "ssf.event.act")]
        SsfEventAct,
        #[serde(rename = "ssf.stream.swept")]
        SsfStreamSwept,
        #[serde(rename = "xacml.pep.enable")]
        XacmlPepEnable,
        #[serde(rename = "xacml.pep.disable")]
        XacmlPepDisable,
        #[serde(rename = "xacml.pep.forget")]
        XacmlPepForget,
        #[serde(rename = "xacml.policy.write")]
        XacmlPolicyWrite,
        #[serde(rename = "xacml.policy.delete")]
        XacmlPolicyDelete,
        #[serde(rename = "report.definition.create")]
        ReportDefinitionCreate,
        #[serde(rename = "report.definition.update")]
        ReportDefinitionUpdate,
        #[serde(rename = "report.definition.share")]
        ReportDefinitionShare,
        #[serde(rename = "report.definition.delete")]
        ReportDefinitionDelete,
        #[serde(rename = "report.job.submit")]
        ReportJobSubmit,
        #[serde(rename = "report.job.start")]
        ReportJobStart,
        #[serde(rename = "report.job.complete")]
        ReportJobComplete,
        #[serde(rename = "report.job.fail")]
        ReportJobFail,
        #[serde(rename = "report.job.cancel")]
        ReportJobCancel,
        #[serde(rename = "report.notify")]
        ReportNotify,
        #[serde(rename = "report.query")]
        ReportQuery,
        #[serde(rename = "report.job.retrieve")]
        ReportJobRetrieve,
        #[serde(rename = "admin.audit-export.add")]
        AdminAuditExportAdd,
        #[serde(rename = "admin.audit-export.update")]
        AdminAuditExportUpdate,
        #[serde(rename = "admin.audit-export.remove")]
        AdminAuditExportRemove,
        #[serde(rename = "admin.audit-export.enable")]
        AdminAuditExportEnable,
        #[serde(rename = "admin.audit-export.disable")]
        AdminAuditExportDisable,
        #[serde(rename = "admin.audit-export.test")]
        AdminAuditExportTest,
        #[serde(rename = "audit.export.test")]
        AuditExportTest,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "success")]
        Success,
        #[serde(rename = "refused")]
        Refused,
        #[serde(rename = "error")]
        Error,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<QueryCategory>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<QueryAction>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::AuditList;
}

/// Check the held audit rows against their checksums
pub mod get_audit_integrity {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/audit/integrity";
    pub const OPERATION_ID: &str = "getAuditIntegrity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MissingItem {
        pub origin: String,
        pub after: i64,
        pub before: i64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Head {
        #[serde(rename = "intact")]
        Intact,
        #[serde(rename = "truncated")]
        Truncated,
        #[serde(rename = "altered")]
        Altered,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub checked: i64,
        pub unsigned: i64,
        pub altered: Vec<i64>,
        pub missing: Vec<Answer200MissingItem>,
        pub head: Answer200Head,
    }
}

/// Every authorization server profile, and what its document says
pub mod get_authorization_servers {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/authorization-servers";
    pub const OPERATION_ID: &str = "getAuthorizationServers";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::AuthorizationServerList;
}

/// Add an authorization server profile
pub mod create_authorization_server {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/authorization-servers/create";
    pub const OPERATION_ID: &str = "createAuthorizationServer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// 1-64 characters of letters, digits, dot, dash, underscore or tilde,
        /// starting with a letter or a digit.
        pub id: String,
        /// Optional display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// Optional note.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors84;
}

/// Delete a profile
pub mod delete_authorization_server {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/authorization-servers/delete";
    pub const OPERATION_ID: &str = "deleteAuthorizationServer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// An alias for `profile`; `asAction()` reads `body.profile || body.id`, so
        /// both spellings have always worked and only one was published.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors84;
}

/// Stop publishing a member at all
pub mod remove_authorization_server_member {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/authorization-servers/remove";
    pub const OPERATION_ID: &str = "removeAuthorizationServerMember";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        pub member: String,
        /// An alias for `profile`; `asAction()` reads `body.profile || body.id`, so
        /// both spellings have always worked and only one was published.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors84;
}

/// Put one member back to what this service publishes
pub mod reset_authorization_server_member {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/authorization-servers/reset";
    pub const OPERATION_ID: &str = "resetAuthorizationServerMember";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        pub member: String,
        /// An alias for `profile`; `asAction()` reads `body.profile || body.id`, so
        /// both spellings have always worked and only one was published.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors84;
}

/// Publish a metadata member with a chosen value
pub mod set_authorization_server_member {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/authorization-servers/set";
    pub const OPERATION_ID: &str = "setAuthorizationServerMember";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The profile id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// Any metadata member name.
        pub member: String,
        /// JSON if it parses as JSON, otherwise the string.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<serde_json::Value>,
        /// An alias for `profile`; `asAction()` reads `body.profile || body.id`, so
        /// both spellings have always worked and only one was published.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors84;
}

/// This realm's sign-in appearance (#717)
pub mod get_branding {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/branding";
    pub const OPERATION_ID: &str = "getBranding";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Colours {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub card: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Derived {
        #[serde(rename = "onAccent", default, skip_serializing_if = "Option::is_none")]
        pub on_accent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub muted: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub faint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dim: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub border: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rule: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Contrast {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accent: Option<f64>,
        #[serde(rename = "buttonText", default, skip_serializing_if = "Option::is_none")]
        pub button_text: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Logo {
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

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub layout: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub layouts: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub colours: Option<Answer200Colours>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub derived: Option<Answer200Derived>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub contrast: Option<Answer200Contrast>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(rename = "logoAlt", default, skip_serializing_if = "Option::is_none")]
        pub logo_alt: Option<String>,
        #[serde(rename = "logoLinkUrl", default, skip_serializing_if = "Option::is_none")]
        pub logo_link_url: Option<String>,
        #[serde(rename = "logoMaxBytes", default, skip_serializing_if = "Option::is_none")]
        pub logo_max_bytes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub logo: Option<Answer200Logo>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub customised: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preview: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "previewUrl", default, skip_serializing_if = "Option::is_none")]
        pub preview_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
    }
}

/// Upload this realm's sign-in logo
pub mod upload_branding_logo {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/branding/logo";
    pub const OPERATION_ID: &str = "uploadBrandingLogo";

    /// The body is not JSON (an upload): its bytes.
    pub type Body = Vec<u8>;

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alt: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors189;
}

/// Remove this realm's sign-in logo
pub mod remove_branding_logo {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/branding/remove-logo";
    pub const OPERATION_ID: &str = "removeBrandingLogo";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors190;
}

/// Change this realm's sign-in appearance
pub mod save_branding {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/branding/save";
    pub const OPERATION_ID: &str = "saveBranding";

    /// centered (the card alone), split (a brand panel beside the card) or banner
    /// (a band above it).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyBrandingLayout {
        #[serde(rename = "centered")]
        Centered,
        #[serde(rename = "split")]
        Split,
        #[serde(rename = "banner")]
        Banner,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// centered (the card alone), split (a brand panel beside the card) or
        /// banner (a band above it).
        #[serde(rename = "branding.layout", default, skip_serializing_if = "Option::is_none")]
        pub branding_layout: Option<BodyBrandingLayout>,
        /// Buttons, links and focus rings, `#rgb` or `#rrggbb`; stored as six
        /// lower-case digits.
        #[serde(rename = "branding.accentColor", default, skip_serializing_if = "Option::is_none")]
        pub branding_accent_color: Option<String>,
        /// The page behind the card, `#rgb` or `#rrggbb`; stored as six lower-case
        /// digits.
        #[serde(rename = "branding.pageColor", default, skip_serializing_if = "Option::is_none")]
        pub branding_page_color: Option<String>,
        /// The card, `#rgb` or `#rrggbb`; stored as six lower-case digits.
        #[serde(rename = "branding.cardColor", default, skip_serializing_if = "Option::is_none")]
        pub branding_card_color: Option<String>,
        /// The text on the card, `#rgb` or `#rrggbb`; stored as six lower-case
        /// digits.
        #[serde(rename = "branding.textColor", default, skip_serializing_if = "Option::is_none")]
        pub branding_text_color: Option<String>,
        /// Shown beside the logo and in the document title. Text, never markup, and
        /// never translated. Empty for none.
        #[serde(rename = "branding.displayName", default, skip_serializing_if = "Option::is_none")]
        pub branding_display_name: Option<String>,
        /// The logo's alternative text. Required while a logo is set.
        #[serde(rename = "branding.logoAlt", default, skip_serializing_if = "Option::is_none")]
        pub branding_logo_alt: Option<String>,
        /// An absolute https URL the logo links to, or empty for no link.
        #[serde(rename = "branding.logoLinkUrl", default, skip_serializing_if = "Option::is_none")]
        pub branding_logo_link_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors190;
}

/// The CAEP session register: what state each session is in and how many events
/// of which type have been sent about it
pub mod get_caep {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/caep";
    pub const OPERATION_ID: &str = "getCaep";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::Caep;
}

/// Drop every row in the CAEP session register
pub mod clear_caep_sessions {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/caep/clear";
    pub const OPERATION_ID: &str = "clearCaepSessions";

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

/// Send one CAEP event about one session
pub mod emit_caep_event {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/caep/emit";
    pub const OPERATION_ID: &str = "emitCaepEvent";

    /// admin | user | policy | system. It is the member that lets a receiver tell
    /// "an administrator revoked this" from "a risk engine did".
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyInitiatingEntity {
        #[serde(rename = "admin")]
        Admin,
        #[serde(rename = "user")]
        User,
        #[serde(rename = "policy")]
        Policy,
        #[serde(rename = "system")]
        System,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The session it is about, from GET /admin-api/caep.
        pub session_id: String,
        /// The event type: a short name such as `session-revoked`, or the whole
        /// URI.
        #[serde(rename = "type")]
        pub type_: String,
        /// admin | user | policy | system. It is the member that lets a receiver
        /// tell "an administrator revoked this" from "a risk engine did".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initiating_entity: Option<BodyInitiatingEntity>,
        /// The event-specific members, as JSON. Empty for a conforming specimen of
        /// the type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<String>,
        /// Why, for a log. Sent as an object keyed by `caep.reasonLanguage` — CAEP
        /// makes it a language map and a string there is the commonest mistake in
        /// the profile.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason_admin: Option<String>,
        /// The same, in words meant for the person.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason_user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors111;
}

/// Put one session's CAEP state back to where it started
pub mod reset_caep_session {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/caep/reset-session";
    pub const OPERATION_ID: &str = "resetCaepSession";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The session.
        pub session_id: String,
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

/// The CAEP session register, searched and paged — or one session with
/// everything that has been said about it
pub mod get_caep_sessions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/caep/sessions";
    pub const OPERATION_ID: &str = "getCaepSessions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<String>,
        #[serde(rename = "sessionsPage", default, skip_serializing_if = "Option::is_none")]
        pub sessions_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appq: Option<String>,
        #[serde(rename = "applicationsPage", default, skip_serializing_if = "Option::is_none")]
        pub applications_page: Option<i64>,
        #[serde(rename = "streamsPage", default, skip_serializing_if = "Option::is_none")]
        pub streams_page: Option<i64>,
        #[serde(rename = "eventsPage", default, skip_serializing_if = "Option::is_none")]
        pub events_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::Caep;
}

/// Whether several nodes against one store behave as one service, and what
/// active-active mode still waits for
pub mod get_cluster_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/cluster";
    pub const OPERATION_ID: &str = "getClusterSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::PageSettings;
}

/// Every setting this service has, and where each value came from
pub mod get_config {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/config";
    pub const OPERATION_ID: &str = "getConfig";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::Config;
}

/// Every configuration parameter, with sensitive values masked
pub mod get_config_dump {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/config-dump";
    pub const OPERATION_ID: &str = "getConfigDump";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    /// `service` from the default realm, `realm` under a realm's prefix.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Scope {
        #[serde(rename = "service")]
        Service,
        #[serde(rename = "realm")]
        Realm,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Masking {
        /// The text that replaces a sensitive value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mask: Option<String>,
        /// How many parameters had a value replaced.
        #[serde(rename = "maskedValues", default, skip_serializing_if = "Option::is_none")]
        pub masked_values: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// The parameters this realm sets itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Vec<sts_model_management_components_2::ParameterSensitiveValuesMasked>>,
    }

    /// The configuration dump.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        /// The format of this document.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        /// This service's version.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        /// `service` from the default realm, `realm` under a realm's prefix.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<Answer200Scope>,
        /// The realm `settings` was read in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub config_file: Option<Option<String>>,
        #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none")]
        pub defaults_file: Option<String>,
        #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
        pub setting_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub masking: Option<Answer200Masking>,
        /// Every parameter, in table order.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Vec<sts_model_management_components_2::ParameterSensitiveValuesMasked>>,
        /// Every other realm. Empty under a realm's prefix.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realms: Option<Vec<Answer200RealmsItem>>,
    }
}

/// Drop one runtime override
pub mod reset_setting {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/config/reset";
    pub const OPERATION_ID: &str = "resetSetting";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub key: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors67;
}

/// Drop every runtime override
pub mod reset_all_settings {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/config/reset-all";
    pub const OPERATION_ID: &str = "resetAllSettings";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors69;
}

/// Change one setting
pub mod set_setting {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/config/set";
    pub const OPERATION_ID: &str = "setSetting";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The dot path, as GET /admin-api/config lists it.
        pub key: String,
        /// A string is always accepted and is coerced to the setting's type, so the
        /// environment spelling works here too; a JSON number, boolean or array of
        /// strings is accepted where the type takes one.
        pub value: serde_json::Value,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors67;
}

/// Change a whole section at once
pub mod set_settings {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/config/set-many";
    pub const OPERATION_ID: &str = "setSettings";

    /// One property per setting, named by its dot path.
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors68;
}

/// Every failure condition this service can produce, and how often each is on
/// the held audit log
pub mod get_error_codes {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/error-codes";
    pub const OPERATION_ID: &str = "getErrorCodes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subsystem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subsystem: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub q: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub seen: Option<Option<bool>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubsystemsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prefix: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codes: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UnregisteredSeenItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<i64>,
        #[serde(rename = "lastSeenAt", default, skip_serializing_if = "Option::is_none")]
        pub last_seen_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CodesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subsystem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retired: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<i64>,
        #[serde(rename = "lastSeenAt", default, skip_serializing_if = "Option::is_none")]
        pub last_seen_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub registered: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retired: Option<i64>,
        #[serde(rename = "subsystemCount", default, skip_serializing_if = "Option::is_none")]
        pub subsystem_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<i64>,
        #[serde(rename = "auditRowsHeld", default, skip_serializing_if = "Option::is_none")]
        pub audit_rows_held: Option<i64>,
        #[serde(rename = "auditRowsWithCode", default, skip_serializing_if = "Option::is_none")]
        pub audit_rows_with_code: Option<i64>,
        #[serde(rename = "distinctCodesSeen", default, skip_serializing_if = "Option::is_none")]
        pub distinct_codes_seen: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
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
        pub documentation: Option<String>,
        #[serde(rename = "neverSentToClients", default, skip_serializing_if = "Option::is_none")]
        pub never_sent_to_clients: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subsystems: Option<Vec<Answer200SubsystemsItem>>,
        #[serde(rename = "unregisteredSeen", default, skip_serializing_if = "Option::is_none")]
        pub unregistered_seen: Option<Vec<Answer200UnregisteredSeenItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codes: Option<Vec<Answer200CodesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
    }
}

/// Who may use the admin console, and how the gate is set
pub mod get_admin_roles {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/rbac";
    pub const OPERATION_ID: &str = "getAdminRoles";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryRole {
        #[serde(rename = "read")]
        Read,
        #[serde(rename = "write")]
        Write,
        #[serde(rename = "security")]
        Security,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<QueryRole>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub personq: Option<String>,
        #[serde(rename = "candidatesPage", default, skip_serializing_if = "Option::is_none")]
        pub candidates_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub personfrom: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub person: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Bootstrap {
        #[serde(rename = "claimedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub claimed_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seeded: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub q: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub role: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200You {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub read: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub write: Option<bool>,
        #[serde(rename = "viaEmptyRoster", default, skip_serializing_if = "Option::is_none")]
        pub via_empty_roster: Option<bool>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub implies: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exists: Option<bool>,
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
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GrantsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(rename = "roleLabel", default, skip_serializing_if = "Option::is_none")]
        pub role_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holds: Option<String>,
        #[serde(rename = "memberDn", default, skip_serializing_if = "Option::is_none")]
        pub member_dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(rename = "userKey", default, skip_serializing_if = "Option::is_none")]
        pub user_key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CandidatesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
        pub in_directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CandidateSearchIncomplete {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unusable: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub short: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capped: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cap: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CandidateSearch {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub q: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<f64>,
        #[serde(rename = "countCapped", default, skip_serializing_if = "Option::is_none")]
        pub count_capped: Option<bool>,
        #[serde(rename = "countCap", default, skip_serializing_if = "Option::is_none")]
        pub count_cap: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub complete: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub incomplete: Option<Answer200CandidateSearchIncomplete>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PickedCandidate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
        pub in_directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Picked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub candidate: Option<Answer200PickedCandidate>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CandidatePaneShownItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
        pub in_directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CandidatePane {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<f64>,
        #[serde(rename = "countCapped", default, skip_serializing_if = "Option::is_none")]
        pub count_capped: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<Vec<Answer200CandidatePaneShownItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RoleChoicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub implies: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(rename = "openWhenEmpty", default, skip_serializing_if = "Option::is_none")]
        pub open_when_empty: Option<bool>,
        #[serde(rename = "openToAnyone", default, skip_serializing_if = "Option::is_none")]
        pub open_to_anyone: Option<bool>,
        #[serde(rename = "closedToEveryone", default, skip_serializing_if = "Option::is_none")]
        pub closed_to_everyone: Option<bool>,
        #[serde(rename = "windowOpens", default, skip_serializing_if = "Option::is_none")]
        pub window_opens: Option<bool>,
        #[serde(rename = "bootstrapPasswordRequired", default, skip_serializing_if = "Option::is_none")]
        pub bootstrap_password_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bootstrap: Option<Answer200Bootstrap>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(rename = "groupsDn", default, skip_serializing_if = "Option::is_none")]
        pub groups_dn: Option<String>,
        #[serde(rename = "usersDn", default, skip_serializing_if = "Option::is_none")]
        pub users_dn: Option<String>,
        #[serde(rename = "grantCount", default, skip_serializing_if = "Option::is_none")]
        pub grant_count: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
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
        pub you: Option<Answer200You>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<Answer200RolesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Vec<Answer200GrantsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub candidates: Option<Vec<Answer200CandidatesItem>>,
        #[serde(rename = "candidatesPaging", default, skip_serializing_if = "Option::is_none")]
        pub candidates_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "candidateSearch", default, skip_serializing_if = "Option::is_none")]
        pub candidate_search: Option<Answer200CandidateSearch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub picked: Option<Answer200Picked>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "candidatePane", default, skip_serializing_if = "Option::is_none")]
        pub candidate_pane: Option<Answer200CandidatePane>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "roleChoices", default, skip_serializing_if = "Option::is_none")]
        pub role_choices: Option<Vec<Answer200RoleChoicesItem>>,
    }
}

/// Give somebody a console role
pub mod grant_admin_role {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/rbac/grant";
    pub const OPERATION_ID: &str = "grantAdminRole";

    /// `write` includes `read`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRole {
        #[serde(rename = "read")]
        Read,
        #[serde(rename = "write")]
        Write,
        #[serde(rename = "security")]
        Security,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The name they sign in as — the same string that appears in a token's
        /// `sub` and on /admin/users.
        pub username: String,
        /// `write` includes `read`.
        pub role: BodyRole,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors61;
}

/// Take a console role away
pub mod revoke_admin_role {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/rbac/revoke";
    pub const OPERATION_ID: &str = "revokeAdminRole";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRole {
        #[serde(rename = "read")]
        Read,
        #[serde(rename = "write")]
        Write,
        #[serde(rename = "security")]
        Security,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Who to take it from.
        pub username: String,
        pub role: BodyRole,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors62;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "addAcmeHostName" => Some(serde_json::from_value::<add_acme_host_name::Body>(value.clone()).map(|_| ())),
        "createAcmeEab" => Some(serde_json::from_value::<create_acme_eab::Body>(value.clone()).map(|_| ())),
        "deactivateAcmeAccount" => Some(serde_json::from_value::<deactivate_acme_account::Body>(value.clone()).map(|_| ())),
        "deleteAcmeEab" => Some(serde_json::from_value::<delete_acme_eab::Body>(value.clone()).map(|_| ())),
        "removeAcmeHostName" => Some(serde_json::from_value::<remove_acme_host_name::Body>(value.clone()).map(|_| ())),
        "revokeAcmeCertificate" => Some(serde_json::from_value::<revoke_acme_certificate::Body>(value.clone()).map(|_| ())),
        "addApplicationValue" => Some(serde_json::from_value::<add_application_value::Body>(value.clone()).map(|_| ())),
        "addApplicationCertificate" => Some(serde_json::from_value::<add_application_certificate::Body>(value.clone()).map(|_| ())),
        "addApplicationOwner" => Some(serde_json::from_value::<add_application_owner::Body>(value.clone()).map(|_| ())),
        "addApplicationClientSecret" => Some(serde_json::from_value::<add_application_client_secret::Body>(value.clone()).map(|_| ())),
        "clearApplicationPermissionClaims" => Some(serde_json::from_value::<clear_application_permission_claims::Body>(value.clone()).map(|_| ())),
        "confirmApplicationReturnAddress" => Some(serde_json::from_value::<confirm_application_return_address::Body>(value.clone()).map(|_| ())),
        "createApplication" => Some(serde_json::from_value::<create_application::Body>(value.clone()).map(|_| ())),
        "discardApplicationReturnAddress" => Some(serde_json::from_value::<discard_application_return_address::Body>(value.clone()).map(|_| ())),
        "exportApplicationLdif" => Some(serde_json::from_value::<export_application_ldif::Body>(value.clone()).map(|_| ())),
        "createApplicationFgaPolicy" => Some(serde_json::from_value::<create_application_fga_policy::Body>(value.clone()).map(|_| ())),
        "disableApplicationFga" => Some(serde_json::from_value::<disable_application_fga::Body>(value.clone()).map(|_| ())),
        "enableApplicationFga" => Some(serde_json::from_value::<enable_application_fga::Body>(value.clone()).map(|_| ())),
        "resetApplicationFgaPolicy" => Some(serde_json::from_value::<reset_application_fga_policy::Body>(value.clone()).map(|_| ())),
        "deleteApplication" => Some(serde_json::from_value::<delete_application::Body>(value.clone()).map(|_| ())),
        "generateApplicationDidKey" => Some(serde_json::from_value::<generate_application_did_key::Body>(value.clone()).map(|_| ())),
        "importApplicationLdif" => Some(serde_json::from_value::<import_application_ldif::Body>(value.clone()).map(|_| ())),
        "inheritApplicationClaimAttributes" => Some(serde_json::from_value::<inherit_application_claim_attributes::Body>(value.clone()).map(|_| ())),
        "issueApplicationSigningCertificate" => Some(serde_json::from_value::<issue_application_signing_certificate::Body>(value.clone()).map(|_| ())),
        "issueApplicationSoftwareStatement" => Some(serde_json::from_value::<issue_application_software_statement::Body>(value.clone()).map(|_| ())),
        "issueApplicationTlsClientCertificate" => Some(serde_json::from_value::<issue_application_tls_client_certificate::Body>(value.clone()).map(|_| ())),
        "loadProtectedResourceMetadata" => Some(serde_json::from_value::<load_protected_resource_metadata::Body>(value.clone()).map(|_| ())),
        "refreshApplicationMetadata" => Some(serde_json::from_value::<refresh_application_metadata::Body>(value.clone()).map(|_| ())),
        "regenerateApplicationClientSecret" => Some(serde_json::from_value::<regenerate_application_client_secret::Body>(value.clone()).map(|_| ())),
        "removeApplicationValue" => Some(serde_json::from_value::<remove_application_value::Body>(value.clone()).map(|_| ())),
        "removeApplicationAccessType" => Some(serde_json::from_value::<remove_application_access_type::Body>(value.clone()).map(|_| ())),
        "removeApplicationAccessTypeRow" => Some(serde_json::from_value::<remove_application_access_type_row::Body>(value.clone()).map(|_| ())),
        "removeApplicationCertificate" => Some(serde_json::from_value::<remove_application_certificate::Body>(value.clone()).map(|_| ())),
        "removeApplicationCustomClaim" => Some(serde_json::from_value::<remove_application_custom_claim::Body>(value.clone()).map(|_| ())),
        "removeApplicationOwner" => Some(serde_json::from_value::<remove_application_owner::Body>(value.clone()).map(|_| ())),
        "removeApplicationClientSecret" => Some(serde_json::from_value::<remove_application_client_secret::Body>(value.clone()).map(|_| ())),
        "revealApplicationSecret" => Some(serde_json::from_value::<reveal_application_secret::Body>(value.clone()).map(|_| ())),
        "revokeApplicationRegistration" => Some(serde_json::from_value::<revoke_application_registration::Body>(value.clone()).map(|_| ())),
        "revokeApplicationSigningCertificate" => Some(serde_json::from_value::<revoke_application_signing_certificate::Body>(value.clone()).map(|_| ())),
        "revokeApplicationTlsClientCertificate" => Some(serde_json::from_value::<revoke_application_tls_client_certificate::Body>(value.clone()).map(|_| ())),
        "rotateApplicationClientSecret" => Some(serde_json::from_value::<rotate_application_client_secret::Body>(value.clone()).map(|_| ())),
        "setApplicationAttribute" => Some(serde_json::from_value::<set_application_attribute::Body>(value.clone()).map(|_| ())),
        "setApplicationAccessType" => Some(serde_json::from_value::<set_application_access_type::Body>(value.clone()).map(|_| ())),
        "setApplicationAccessTypeRow" => Some(serde_json::from_value::<set_application_access_type_row::Body>(value.clone()).map(|_| ())),
        "setApplicationClaimAttributes" => Some(serde_json::from_value::<set_application_claim_attributes::Body>(value.clone()).map(|_| ())),
        "setApplicationClaimSelections" => Some(serde_json::from_value::<set_application_claim_selections::Body>(value.clone()).map(|_| ())),
        "setApplicationCustomClaim" => Some(serde_json::from_value::<set_application_custom_claim::Body>(value.clone()).map(|_| ())),
        "setApplicationAccessTypeNotForPolicy" => Some(serde_json::from_value::<set_application_access_type_not_for_policy::Body>(value.clone()).map(|_| ())),
        "setApplicationPermissionClaims" => Some(serde_json::from_value::<set_application_permission_claims::Body>(value.clone()).map(|_| ())),
        "signApplicationDomainLinkage" => Some(serde_json::from_value::<sign_application_domain_linkage::Body>(value.clone()).map(|_| ())),
        "updateApplicationFields" => Some(serde_json::from_value::<update_application_fields::Body>(value.clone()).map(|_| ())),
        "createAuthorizationServer" => Some(serde_json::from_value::<create_authorization_server::Body>(value.clone()).map(|_| ())),
        "deleteAuthorizationServer" => Some(serde_json::from_value::<delete_authorization_server::Body>(value.clone()).map(|_| ())),
        "removeAuthorizationServerMember" => Some(serde_json::from_value::<remove_authorization_server_member::Body>(value.clone()).map(|_| ())),
        "resetAuthorizationServerMember" => Some(serde_json::from_value::<reset_authorization_server_member::Body>(value.clone()).map(|_| ())),
        "setAuthorizationServerMember" => Some(serde_json::from_value::<set_authorization_server_member::Body>(value.clone()).map(|_| ())),
        "removeBrandingLogo" => Some(serde_json::from_value::<remove_branding_logo::Body>(value.clone()).map(|_| ())),
        "saveBranding" => Some(serde_json::from_value::<save_branding::Body>(value.clone()).map(|_| ())),
        "clearCaepSessions" => Some(serde_json::from_value::<clear_caep_sessions::Body>(value.clone()).map(|_| ())),
        "emitCaepEvent" => Some(serde_json::from_value::<emit_caep_event::Body>(value.clone()).map(|_| ())),
        "resetCaepSession" => Some(serde_json::from_value::<reset_caep_session::Body>(value.clone()).map(|_| ())),
        "resetSetting" => Some(serde_json::from_value::<reset_setting::Body>(value.clone()).map(|_| ())),
        "resetAllSettings" => Some(serde_json::from_value::<reset_all_settings::Body>(value.clone()).map(|_| ())),
        "setSetting" => Some(serde_json::from_value::<set_setting::Body>(value.clone()).map(|_| ())),
        "setSettings" => Some(serde_json::from_value::<set_settings::Body>(value.clone()).map(|_| ())),
        "grantAdminRole" => Some(serde_json::from_value::<grant_admin_role::Body>(value.clone()).map(|_| ())),
        "revokeAdminRole" => Some(serde_json::from_value::<revoke_admin_role::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getAcme", 200) => Some(serde_json::from_value::<get_acme::Answer200>(value.clone()).map(|_| ())),
        ("addAcmeHostName", 200) => Some(serde_json::from_value::<add_acme_host_name::Answer200>(value.clone()).map(|_| ())),
        ("createAcmeEab", 200) => Some(serde_json::from_value::<create_acme_eab::Answer200>(value.clone()).map(|_| ())),
        ("deactivateAcmeAccount", 200) => Some(serde_json::from_value::<deactivate_acme_account::Answer200>(value.clone()).map(|_| ())),
        ("deleteAcmeEab", 200) => Some(serde_json::from_value::<delete_acme_eab::Answer200>(value.clone()).map(|_| ())),
        ("getAcmeMonitor", 200) => Some(serde_json::from_value::<get_acme_monitor::Answer200>(value.clone()).map(|_| ())),
        ("removeAcmeHostName", 200) => Some(serde_json::from_value::<remove_acme_host_name::Answer200>(value.clone()).map(|_| ())),
        ("revokeAcmeCertificate", 200) => Some(serde_json::from_value::<revoke_acme_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getApplications", 200) => Some(serde_json::from_value::<get_applications::Answer200>(value.clone()).map(|_| ())),
        ("addApplicationValue", 200) => Some(serde_json::from_value::<add_application_value::Answer200>(value.clone()).map(|_| ())),
        ("addApplicationCertificate", 200) => Some(serde_json::from_value::<add_application_certificate::Answer200>(value.clone()).map(|_| ())),
        ("addApplicationOwner", 200) => Some(serde_json::from_value::<add_application_owner::Answer200>(value.clone()).map(|_| ())),
        ("addApplicationClientSecret", 200) => Some(serde_json::from_value::<add_application_client_secret::Answer200>(value.clone()).map(|_| ())),
        ("clearApplicationPermissionClaims", 200) => Some(serde_json::from_value::<clear_application_permission_claims::Answer200>(value.clone()).map(|_| ())),
        ("confirmApplicationReturnAddress", 200) => Some(serde_json::from_value::<confirm_application_return_address::Answer200>(value.clone()).map(|_| ())),
        ("createApplication", 200) => Some(serde_json::from_value::<create_application::Answer200>(value.clone()).map(|_| ())),
        ("discardApplicationReturnAddress", 200) => Some(serde_json::from_value::<discard_application_return_address::Answer200>(value.clone()).map(|_| ())),
        ("exportApplicationLdif", 200) => Some(serde_json::from_value::<export_application_ldif::Answer200>(value.clone()).map(|_| ())),
        ("createApplicationFgaPolicy", 200) => Some(serde_json::from_value::<create_application_fga_policy::Answer200>(value.clone()).map(|_| ())),
        ("disableApplicationFga", 200) => Some(serde_json::from_value::<disable_application_fga::Answer200>(value.clone()).map(|_| ())),
        ("enableApplicationFga", 200) => Some(serde_json::from_value::<enable_application_fga::Answer200>(value.clone()).map(|_| ())),
        ("resetApplicationFgaPolicy", 200) => Some(serde_json::from_value::<reset_application_fga_policy::Answer200>(value.clone()).map(|_| ())),
        ("deleteApplication", 200) => Some(serde_json::from_value::<delete_application::Answer200>(value.clone()).map(|_| ())),
        ("generateApplicationDidKey", 200) => Some(serde_json::from_value::<generate_application_did_key::Answer200>(value.clone()).map(|_| ())),
        ("importApplicationLdif", 200) => Some(serde_json::from_value::<import_application_ldif::Answer200>(value.clone()).map(|_| ())),
        ("inheritApplicationClaimAttributes", 200) => Some(serde_json::from_value::<inherit_application_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("issueApplicationSigningCertificate", 200) => Some(serde_json::from_value::<issue_application_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("issueApplicationSoftwareStatement", 200) => Some(serde_json::from_value::<issue_application_software_statement::Answer200>(value.clone()).map(|_| ())),
        ("issueApplicationTlsClientCertificate", 200) => Some(serde_json::from_value::<issue_application_tls_client_certificate::Answer200>(value.clone()).map(|_| ())),
        ("loadProtectedResourceMetadata", 200) => Some(serde_json::from_value::<load_protected_resource_metadata::Answer200>(value.clone()).map(|_| ())),
        ("getNewApplicationForm", 200) => Some(serde_json::from_value::<get_new_application_form::Answer200>(value.clone()).map(|_| ())),
        ("refreshApplicationMetadata", 200) => Some(serde_json::from_value::<refresh_application_metadata::Answer200>(value.clone()).map(|_| ())),
        ("regenerateApplicationClientSecret", 200) => Some(serde_json::from_value::<regenerate_application_client_secret::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationValue", 200) => Some(serde_json::from_value::<remove_application_value::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationAccessType", 200) => Some(serde_json::from_value::<remove_application_access_type::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationAccessTypeRow", 200) => Some(serde_json::from_value::<remove_application_access_type_row::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationCertificate", 200) => Some(serde_json::from_value::<remove_application_certificate::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationCustomClaim", 200) => Some(serde_json::from_value::<remove_application_custom_claim::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationOwner", 200) => Some(serde_json::from_value::<remove_application_owner::Answer200>(value.clone()).map(|_| ())),
        ("removeApplicationClientSecret", 200) => Some(serde_json::from_value::<remove_application_client_secret::Answer200>(value.clone()).map(|_| ())),
        ("revealApplicationSecret", 200) => Some(serde_json::from_value::<reveal_application_secret::Answer200>(value.clone()).map(|_| ())),
        ("revokeApplicationRegistration", 200) => Some(serde_json::from_value::<revoke_application_registration::Answer200>(value.clone()).map(|_| ())),
        ("revokeApplicationSigningCertificate", 200) => Some(serde_json::from_value::<revoke_application_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("revokeApplicationTlsClientCertificate", 200) => Some(serde_json::from_value::<revoke_application_tls_client_certificate::Answer200>(value.clone()).map(|_| ())),
        ("rotateApplicationClientSecret", 200) => Some(serde_json::from_value::<rotate_application_client_secret::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationAttribute", 200) => Some(serde_json::from_value::<set_application_attribute::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationAccessType", 200) => Some(serde_json::from_value::<set_application_access_type::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationAccessTypeRow", 200) => Some(serde_json::from_value::<set_application_access_type_row::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationClaimAttributes", 200) => Some(serde_json::from_value::<set_application_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationClaimSelections", 200) => Some(serde_json::from_value::<set_application_claim_selections::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationCustomClaim", 200) => Some(serde_json::from_value::<set_application_custom_claim::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationAccessTypeNotForPolicy", 200) => Some(serde_json::from_value::<set_application_access_type_not_for_policy::Answer200>(value.clone()).map(|_| ())),
        ("setApplicationPermissionClaims", 200) => Some(serde_json::from_value::<set_application_permission_claims::Answer200>(value.clone()).map(|_| ())),
        ("signApplicationDomainLinkage", 200) => Some(serde_json::from_value::<sign_application_domain_linkage::Answer200>(value.clone()).map(|_| ())),
        ("updateApplicationFields", 200) => Some(serde_json::from_value::<update_application_fields::Answer200>(value.clone()).map(|_| ())),
        ("getAudit", 200) => Some(serde_json::from_value::<get_audit::Answer200>(value.clone()).map(|_| ())),
        ("getAuditIntegrity", 200) => Some(serde_json::from_value::<get_audit_integrity::Answer200>(value.clone()).map(|_| ())),
        ("getAuthorizationServers", 200) => Some(serde_json::from_value::<get_authorization_servers::Answer200>(value.clone()).map(|_| ())),
        ("createAuthorizationServer", 200) => Some(serde_json::from_value::<create_authorization_server::Answer200>(value.clone()).map(|_| ())),
        ("deleteAuthorizationServer", 200) => Some(serde_json::from_value::<delete_authorization_server::Answer200>(value.clone()).map(|_| ())),
        ("removeAuthorizationServerMember", 200) => Some(serde_json::from_value::<remove_authorization_server_member::Answer200>(value.clone()).map(|_| ())),
        ("resetAuthorizationServerMember", 200) => Some(serde_json::from_value::<reset_authorization_server_member::Answer200>(value.clone()).map(|_| ())),
        ("setAuthorizationServerMember", 200) => Some(serde_json::from_value::<set_authorization_server_member::Answer200>(value.clone()).map(|_| ())),
        ("getBranding", 200) => Some(serde_json::from_value::<get_branding::Answer200>(value.clone()).map(|_| ())),
        ("uploadBrandingLogo", 200) => Some(serde_json::from_value::<upload_branding_logo::Answer200>(value.clone()).map(|_| ())),
        ("removeBrandingLogo", 200) => Some(serde_json::from_value::<remove_branding_logo::Answer200>(value.clone()).map(|_| ())),
        ("saveBranding", 200) => Some(serde_json::from_value::<save_branding::Answer200>(value.clone()).map(|_| ())),
        ("getCaep", 200) => Some(serde_json::from_value::<get_caep::Answer200>(value.clone()).map(|_| ())),
        ("clearCaepSessions", 200) => Some(serde_json::from_value::<clear_caep_sessions::Answer200>(value.clone()).map(|_| ())),
        ("emitCaepEvent", 200) => Some(serde_json::from_value::<emit_caep_event::Answer200>(value.clone()).map(|_| ())),
        ("resetCaepSession", 200) => Some(serde_json::from_value::<reset_caep_session::Answer200>(value.clone()).map(|_| ())),
        ("getCaepSessions", 200) => Some(serde_json::from_value::<get_caep_sessions::Answer200>(value.clone()).map(|_| ())),
        ("getClusterSettings", 200) => Some(serde_json::from_value::<get_cluster_settings::Answer200>(value.clone()).map(|_| ())),
        ("getConfig", 200) => Some(serde_json::from_value::<get_config::Answer200>(value.clone()).map(|_| ())),
        ("getConfigDump", 200) => Some(serde_json::from_value::<get_config_dump::Answer200>(value.clone()).map(|_| ())),
        ("resetSetting", 200) => Some(serde_json::from_value::<reset_setting::Answer200>(value.clone()).map(|_| ())),
        ("resetAllSettings", 200) => Some(serde_json::from_value::<reset_all_settings::Answer200>(value.clone()).map(|_| ())),
        ("setSetting", 200) => Some(serde_json::from_value::<set_setting::Answer200>(value.clone()).map(|_| ())),
        ("setSettings", 200) => Some(serde_json::from_value::<set_settings::Answer200>(value.clone()).map(|_| ())),
        ("getErrorCodes", 200) => Some(serde_json::from_value::<get_error_codes::Answer200>(value.clone()).map(|_| ())),
        ("getAdminRoles", 200) => Some(serde_json::from_value::<get_admin_roles::Answer200>(value.clone()).map(|_| ())),
        ("grantAdminRole", 200) => Some(serde_json::from_value::<grant_admin_role::Answer200>(value.clone()).map(|_| ())),
        ("revokeAdminRole", 200) => Some(serde_json::from_value::<revoke_admin_role::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
