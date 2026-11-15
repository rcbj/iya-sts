// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// Every service account and the state of its rotation
pub mod get_service_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/service-accounts";
    pub const OPERATION_ID: &str = "getServiceAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failing: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Policy {
        #[serde(rename = "rotationEnabled", default, skip_serializing_if = "Option::is_none")]
        pub rotation_enabled: Option<bool>,
        #[serde(rename = "intervalDays", default, skip_serializing_if = "Option::is_none")]
        pub interval_days: Option<f64>,
        #[serde(rename = "overlapMinutes", default, skip_serializing_if = "Option::is_none")]
        pub overlap_minutes: Option<f64>,
        #[serde(rename = "alarmFailures", default, skip_serializing_if = "Option::is_none")]
        pub alarm_failures: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Totals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<f64>,
        #[serde(rename = "withDestination", default, skip_serializing_if = "Option::is_none")]
        pub with_destination: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rotating: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failing: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alarms: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failing: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AccountsItemOwnersItem {
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
    pub struct Answer200AccountsItemOwnership {
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
    pub struct Answer200AccountsItemRotation {
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
    pub struct Answer200AccountsItemPolicy {
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
    pub struct Answer200AccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<Vec<Answer200AccountsItemOwnersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ownership: Option<Answer200AccountsItemOwnership>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub destination: Option<Option<String>>,
        #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub secret_name: Option<Option<String>>,
        #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub rotated_at: Option<Option<String>>,
        #[serde(rename = "previousPasswordUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub previous_password_until: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rotation: Option<Answer200AccountsItemRotation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Answer200AccountsItemPolicy>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Answer200Policy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200AccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<sts_model_management_components_3::ServiceAccountView>,
    }
}

/// Everyone this service has authenticated, or one of them in full
pub mod get_users {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users";
    pub const OPERATION_ID: &str = "getUsers";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFactor {
        #[serde(rename = "any")]
        Any,
        #[serde(rename = "totp")]
        Totp,
        #[serde(rename = "key")]
        Key,
        #[serde(rename = "none")]
        None,
        #[serde(rename = "unreadable")]
        Unreadable,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryKind {
        #[serde(rename = "service")]
        Service,
        #[serde(rename = "person")]
        Person,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<QueryFactor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<QueryKind>,
        #[serde(rename = "authenticationsPage", default, skip_serializing_if = "Option::is_none")]
        pub authentications_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "sessionsPage", default, skip_serializing_if = "Option::is_none")]
        pub sessions_page: Option<i64>,
        #[serde(rename = "tokensOnEndedSessionsPage", default, skip_serializing_if = "Option::is_none")]
        pub tokens_on_ended_sessions_page: Option<i64>,
        #[serde(rename = "tokensWithNoSessionPage", default, skip_serializing_if = "Option::is_none")]
        pub tokens_with_no_session_page: Option<i64>,
        #[serde(rename = "artifactsPage", default, skip_serializing_if = "Option::is_none")]
        pub artifacts_page: Option<i64>,
        #[serde(rename = "federationLinksPage", default, skip_serializing_if = "Option::is_none")]
        pub federation_links_page: Option<i64>,
        #[serde(rename = "gnapGrantsPage", default, skip_serializing_if = "Option::is_none")]
        pub gnap_grants_page: Option<i64>,
        #[serde(rename = "umaPage", default, skip_serializing_if = "Option::is_none")]
        pub uma_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200V3 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<bool>,
        #[serde(rename = "registryKeeps", default, skip_serializing_if = "Option::is_none")]
        pub registry_keeps: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200 {
        UserList(sts_model_management_components_3::UserList),
        UserDetail(sts_model_management_components_3::UserDetail),
        V3(Answer200V3),
    }
}

/// Add a value to one of somebody's multi-valued attributes
pub mod add_user_attribute_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/add-attribute";
    pub const OPERATION_ID: &str = "addUserAttributeValue";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The attribute, as `attributeEditor.attributes[].name` in GET
        /// /admin-api/users?user= names it.
        pub attribute: String,
        /// The value to add.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors23;
}

/// Store a certificate on somebody's entry, so an outside certificate
/// authority's certificate signs them in
pub mod add_user_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/add-certificate";
    pub const OPERATION_ID: &str = "addUserCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The leaf, as one PEM block or base64 DER.
        pub certificate: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors38;
}

/// Add one owner to a service account
pub mod add_service_account_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/add-service-account-owner";
    pub const OPERATION_ID: &str = "addServiceAccountOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service account, as /admin-api/users names it.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The person or group to add.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors31;
}

/// Approve or deny a CIBA request waiting for somebody (development test
/// control)
pub mod answer_user_ciba_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/answer-ciba-request";
    pub const OPERATION_ID: &str = "answerUserCibaRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The request's auth_req_id.
        pub id: String,
        /// true approves, false denies.
        pub approve: bool,
        /// The level the approval is recorded as reaching.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors36;
}

/// One person's app passwords, and which password-only doors refuse their own
/// password
pub mod get_user_app_passwords {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/app-passwords";
    pub const OPERATION_ID: &str = "getUserAppPasswords";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        pub user: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DoorsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasswordOnlyDoors {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<Answer200DoorsItem>>,
        #[serde(rename = "passwordOnlyDoors", default, skip_serializing_if = "Option::is_none")]
        pub password_only_doors: Option<Answer200PasswordOnlyDoors>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passwords: Option<Vec<sts_model_management_components_4::WithIdNameDoors>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }
}

/// Begin enrolling a passkey for somebody, in your own browser
pub mod begin_user_passkey_enrolment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/begin-passkey-enrolment";
    pub const OPERATION_ID: &str = "beginUserPasskeyEnrolment";

    /// The lane (#643) where the realm offers both
    /// (webauthn.pqcAlongsideClassical); the classical one otherwise.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyLane {
        #[serde(rename = "classical")]
        Classical,
        #[serde(rename = "pqc")]
        Pqc,
    }

    /// Which kind of authenticator to ask for; the realm's attachment setting
    /// decides either way.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "passkey")]
        Passkey,
        #[serde(rename = "security-key")]
        SecurityKey,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// Ignored since #1135: a passkey has no role. Accepted so that an older
        /// body is not refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        /// The lane (#643) where the realm offers both
        /// (webauthn.pqcAlongsideClassical); the classical one otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<BodyLane>,
        /// Which kind of authenticator to ask for; the realm's attachment setting
        /// decides either way.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKind>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors52;
}

/// Begin upgrading a person's classical passkey
pub mod begin_user_passkey_upgrade {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/begin-passkey-upgrade";
    pub const OPERATION_ID: &str = "beginUserPasskeyUpgrade";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub user: String,
        #[serde(rename = "credentialId")]
        pub credential_id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors49;
}

/// Cancel a person's pending passkey upgrade
pub mod cancel_user_passkey_upgrade {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/cancel-passkey-upgrade";
    pub const OPERATION_ID: &str = "cancelUserPasskeyUpgrade";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub user: String,
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

/// The certificates stored on one person's entry (userCertificate)
pub mod get_user_certificates {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/certificates";
    pub const OPERATION_ID: &str = "getUserCertificates";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub user: String,
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
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<sts_model_management_components_4::WithSubjectLabelEnrolledAt>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rule: Option<String>,
    }
}

/// Clear somebody's recovery codes
pub mod clear_user_backup_codes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/clear-backup-codes";
    pub const OPERATION_ID: &str = "clearUserBackupCodes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors20;
}

/// Turn off somebody's emailed second factor
pub mod clear_user_email_factor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/clear-email-factor";
    pub const OPERATION_ID: &str = "clearUserEmailFactor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors21;
}

/// Remove one of somebody's security keys
pub mod clear_user_security_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/clear-key";
    pub const OPERATION_ID: &str = "clearUserSecurityKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// base64url, as WebAuthn produced it.
        #[serde(rename = "credentialId")]
        pub credential_id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors20;
}

/// Clear somebody's authenticator app enrolment
pub mod clear_user_authenticator_app {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/clear-totp";
    pub const OPERATION_ID: &str = "clearUserAuthenticatorApp";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors20;
}

/// Put a person in the directory before they authenticate
pub mod create_user {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/create";
    pub const OPERATION_ID: &str = "createUser";

    /// How they first get in. **`generate` is the DEFAULT since 2026-09-12**: a
    /// password drawn to satisfy this realm's password policy (`GET
    /// /admin-api/policies`), set, and RETURNED ONCE in `password` — this service
    /// stores a scrypt hash and cannot produce it again. It costs one hash per
    /// create, about 70ms, so a bulk load that wants nobody holding anything sends
    /// `none`. `none` was the default before, and in development mode it is enough
    /// to sign in, since no password is checked there; `password`, hashing the
    /// `password` field onto the entry, and refused by the password policy in
    /// product mode when it does not meet it; `activation`, issuing a single-use
    /// link and returning it ONCE in `activationUrl` for you to send them, at which
    /// they choose a password, a security key or both. **A CREDENTIAL STEP THAT
    /// FAILS DOES NOT UNDO THE CREATE.** A password can only be written onto an
    /// entry that exists, so the person is there either way; the reply is `ok:
    /// true` with `credentialError` set and says so, because answering `ok: false`
    /// would send a caller to create them again and meet "that username is taken".
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyCredential {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "generate")]
        Generate,
        #[serde(rename = "activation")]
        Activation,
    }

    /// With `credential: activation`, `mail` (#63) sends the link to the address on
    /// the person's entry through the realm's mail transport and does NOT return
    /// it: the answer carries `mailedTo`. If it cannot be mailed the link is
    /// returned as with `show` (the default), with `mailError` saying why.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDeliver {
        #[serde(rename = "show")]
        Show,
        #[serde(rename = "mail")]
        Mail,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The name they will authenticate under — the same string that appears in
        /// a token's `sub` and on /admin/users. Not a DN and not a `did:`, and it
        /// may not carry a character RFC 4514 reserves in a DN: those name entries
        /// that get here by being presented rather than by being created.
        pub username: String,
        /// Optional. What the entry's `description` says about why it exists; the
        /// default says it was created by hand rather than by authenticating. An
        /// `attributes.description` wins over it, because an operator's own
        /// sentence about a person is the more useful one and two values would be
        /// the entry answering the question twice.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        /// What is known about them, as `{attribute: value}`. The names are the
        /// catalogue `GET /admin-api/users/new` publishes, in that document's own
        /// spelling, and they are the names the entry carries — so an `ldapsearch`
        /// shows exactly what was sent. **A NAME THAT IS NOT ON THE CATALOGUE IS
        /// REFUSED and the whole create fails**, rather than the value being
        /// ignored: silently dropping it would answer "created" to a request asking
        /// for something this did not do. `userPassword` is refused by that rule —
        /// use `credential` — and so is `uid`, which is `username`. An empty string
        /// is the same as sending nothing: the attribute is absent from the entry
        /// rather than present and empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
        /// Whether to MAKE UP the attributes not sent. **Defaults to TRUE**, which
        /// is what this operation has always done and what its own description
        /// above promises: `vc_claims.js` invents a consistent person per username,
        /// so the entry and any credential issued for them agree from the start.
        /// Send `false` for an entry carrying ONLY what you sent — its object
        /// classes, its uid, a description and your attributes. That is what the
        /// console's form does. It is not a promise the entry stays that way: the
        /// Populate button on /admin/vc fills every missing SELECTED attribute on
        /// every person, and does not know which were typed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub invent: Option<bool>,
        /// How they first get in. **`generate` is the DEFAULT since 2026-09-12**: a
        /// password drawn to satisfy this realm's password policy (`GET
        /// /admin-api/policies`), set, and RETURNED ONCE in `password` — this
        /// service stores a scrypt hash and cannot produce it again. It costs one
        /// hash per create, about 70ms, so a bulk load that wants nobody holding
        /// anything sends `none`. `none` was the default before, and in development
        /// mode it is enough to sign in, since no password is checked there;
        /// `password`, hashing the `password` field onto the entry, and refused by
        /// the password policy in product mode when it does not meet it;
        /// `activation`, issuing a single-use link and returning it ONCE in
        /// `activationUrl` for you to send them, at which they choose a password, a
        /// security key or both. **A CREDENTIAL STEP THAT FAILS DOES NOT UNDO THE
        /// CREATE.** A password can only be written onto an entry that exists, so
        /// the person is there either way; the reply is `ok: true` with
        /// `credentialError` set and says so, because answering `ok: false` would
        /// send a caller to create them again and meet "that username is taken".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<BodyCredential>,
        /// Read only when `credential` is `password`. Hashed with scrypt by
        /// credentials.js and never stored or logged in the clear; nothing in this
        /// service can show it again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// Optional, and CHECKED WHERE SENT: the console's form always sends it,
        /// because a mistyped password nobody can read back is a person who cannot
        /// sign in and nobody who can say why. An API caller with one value has
        /// nothing to mistype against and may omit it.
        #[serde(rename = "passwordConfirm", default, skip_serializing_if = "Option::is_none")]
        pub password_confirm: Option<String>,
        /// Create the person as a SERVICE ACCOUNT (#221): a person entry carrying
        /// `stsServiceAccount`, governed by the realm's service-account policy.
        /// `owners`, and `destination` with `secretName`, are read with it, and
        /// checked BEFORE the person is created — a refusal creates nobody.
        #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
        pub service_account: Option<bool>,
        /// With `serviceAccount`: the people and groups answerable for it (#600) —
        /// each a DN, a username or a group's cn; an array, or a string of one per
        /// line. At least one while the policy's `requireOwner` is on (the
        /// default).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<sts_model_base::unions::StringOrList>,
        /// With `serviceAccount`: the DN of the push destination (an application
        /// entry) its rotated password is written to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination: Option<String>,
        /// With `destination`: the secret's name or path there, which must already
        /// exist.
        #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none")]
        pub secret_name: Option<String>,
        /// With `credential: activation`, `mail` (#63) sends the link to the
        /// address on the person's entry through the realm's mail transport and
        /// does NOT return it: the answer carries `mailedTo`. If it cannot be
        /// mailed the link is returned as with `show` (the default), with
        /// `mailError` saying why.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliver: Option<BodyDeliver>,
        /// Only when this service is deployed as cells (#98): the id of the cell
        /// the person is homed in. Empty means the realm's `cells.homeCell`, or the
        /// cell that answers. Another cell's id makes the creation THERE; a cell
        /// the service does not have, or one in a jurisdiction the realm does not
        /// allow, is refused 400. Ignored in single-cell mode.
        #[serde(rename = "homeCell", default, skip_serializing_if = "Option::is_none")]
        pub home_cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors18;
}

/// Make an app password for somebody, returned once
pub mod create_user_app_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/create-app-password";
    pub const OPERATION_ID: &str = "createUserAppPassword";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDoorsItem {
        #[serde(rename = "ldap")]
        Ldap,
        #[serde(rename = "wstrust")]
        Wstrust,
        #[serde(rename = "scim")]
        Scim,
        #[serde(rename = "ssf")]
        Ssf,
        #[serde(rename = "est")]
        Est,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// What it is for — the client it goes in. At most 64 characters, unique
        /// among this person's.
        pub name: String,
        /// The doors it is accepted at. At least one.
        pub doors: Vec<BodyDoorsItem>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors47;
}

/// Deactivate a did:web this realm publishes for somebody
pub mod deactivate_user_published_did {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/deactivate-published-did";
    pub const OPERATION_ID: &str = "deactivateUserPublishedDid";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The DID, or its random id (`rid`), as GET
        /// /admin-api/users/published-dids lists it.
        pub did: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors43;
}

/// One person's devices (ou=devices)
pub mod get_user_devices {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/devices";
    pub const OPERATION_ID: &str = "getUserDevices";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        pub user: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItemKeysItemAttestationRevocation {
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
    pub struct Answer200DevicesItemKeysItemAttestationFreshness {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItemKeysItemAttestation {
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
        pub revocation: Option<Answer200DevicesItemKeysItemAttestationRevocation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub freshness: Option<Answer200DevicesItemKeysItemAttestationFreshness>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItemKeysItem {
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
        pub attestation: Option<Answer200DevicesItemKeysItemAttestation>,
        /// A device key's public material as its kind carries it: a client's JWK, a
        /// certificate, or a WebAuthn credential.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub material: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItemAttestation {
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
    pub struct Answer200DevicesItemEnrolment {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItemRememberedBrowser {
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
    pub struct Answer200DevicesItem {
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
        pub keys: Option<Vec<Answer200DevicesItemKeysItem>>,
        #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
        pub key_kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<Answer200DevicesItemAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<String>,
        #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
        pub compliance_change: Option<sts_model_management_components_1::ComplianceChangeValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
        pub status_change: Option<sts_model_management_components_1::ComplianceChangeValue>,
        #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
        pub risk_level: Option<String>,
        #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
        pub risk_change: Option<sts_model_management_components_1::ComplianceChangeValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<Answer200DevicesItemEnrolment>,
        #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
        pub native_sso: Option<bool>,
        #[serde(rename = "rememberedBrowser", default, skip_serializing_if = "Option::is_none")]
        pub remembered_browser: Option<Answer200DevicesItemRememberedBrowser>,
        #[serde(rename = "sessionLive", default, skip_serializing_if = "Option::is_none")]
        pub session_live: Option<bool>,
        #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub devices: Option<Vec<Answer200DevicesItem>>,
    }
}

/// Disable somebody's account, and end everything they hold
pub mod disable_user_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/disable";
    pub const OPERATION_ID: &str = "disableUserAccount";

    /// RISC account-disabled's `reason` (section 2.2), sent to receivers; omitted
    /// when not given (#146).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRiscReason {
        #[serde(rename = "hijacking")]
        Hijacking,
        #[serde(rename = "bulk-account")]
        BulkAccount,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// Recorded on the audit row.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// RISC account-disabled's `reason` (section 2.2), sent to receivers;
        /// omitted when not given (#146).
        #[serde(rename = "riscReason", default, skip_serializing_if = "Option::is_none")]
        pub risc_reason: Option<BodyRiscReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors45;
}

/// Remove every second factor somebody holds
pub mod disable_user_second_factors {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/disable-mfa";
    pub const OPERATION_ID: &str = "disableUserSecondFactors";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors28;
}

/// Remove every passkey somebody holds
pub mod disable_user_passkeys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/disable-primary-keys";
    pub const OPERATION_ID: &str = "disableUserPasskeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors27;
}

/// Enable a disabled account again
pub mod enable_user_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/enable";
    pub const OPERATION_ID: &str = "enableUserAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// Recorded on the audit row.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors45;
}

/// Enrol a self-issued (SIOPv2) subject for somebody
pub mod enrol_user_self_issued_subject {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/enrol-self-issued-subject";
    pub const OPERATION_ID: &str = "enrolUserSelfIssuedSubject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The DID, thumbprint or JWK.
        pub subject: String,
        /// A name for it, at most 64 characters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors41;
}

/// Export one person's entry as an LDIF file
pub mod export_user_ldif {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/export-ldif";
    pub const OPERATION_ID: &str = "exportUserLdif";

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
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
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

    pub type Answer200 = sts_model_management_components_3::UserLdifExportAnswer;
}

/// Link a federation partner's subject to a person
pub mod link_user_federation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/federation-link";
    pub const OPERATION_ID: &str = "linkUserFederation";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The service-provider-side relationship the link is through.
        pub relationship: String,
        /// The partner's identifier for the person.
        pub subject: String,
        /// The partner's entity ID or `iss`; the relationship's fedPeer when
        /// omitted, and refused if it differs from it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors46;
}

/// Remove a federation partner's link from a person, and end the sessions it
/// made
pub mod unlink_user_federation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/federation-unlink";
    pub const OPERATION_ID: &str = "unlinkUserFederation";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The whole value, as `federationLinks[].link` shows it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<String>,
        /// Instead of `link`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationship: Option<String>,
        /// Instead of `link`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        /// Instead of `link`; the relationship's fedPeer when omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors46;
}

/// Finish enrolling a passkey for somebody
pub mod finish_user_passkey_enrolment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/finish-passkey-enrolment";
    pub const OPERATION_ID: &str = "finishUserPasskeyEnrolment";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The `enrolmentId` the begin answered.
        #[serde(rename = "enrolmentId")]
        pub enrolment_id: String,
        /// The browser's registration as JSON: `id`, `rawId`, `type`,
        /// `authenticatorAttachment`, `clientExtensionResults` and `response`
        /// (`clientDataJSON`, `attestationObject`, `transports`), base64url — or `{
        /// error, message }` where the browser refused.
        pub credential: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors53;
}

/// Finish upgrading a person's passkey
pub mod finish_user_passkey_upgrade {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/finish-passkey-upgrade";
    pub const OPERATION_ID: &str = "finishUserPasskeyUpgrade";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub user: String,
        #[serde(rename = "upgradeId")]
        pub upgrade_id: String,
        pub credential: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors51;
}

/// Create a person from an LDIF file
pub mod import_user_ldif {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/import-ldif";
    pub const OPERATION_ID: &str = "importUserLdif";

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

    pub type Answer200 = sts_model_management_components_3::UserLdifImportAnswer;
}

/// Issue a one-time activation link for a provisioned person
pub mod issue_activation_link {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/issue-activation";
    pub const OPERATION_ID: &str = "issueActivationLink";

    /// `mail` (#63) sends the link to the address on the person's entry through the
    /// realm's mail transport and does NOT return it: the answer carries
    /// `mailedTo`. If it cannot be mailed the link is returned as with `show` (the
    /// default), with `mailError` saying why.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDeliver {
        #[serde(rename = "show")]
        Show,
        #[serde(rename = "mail")]
        Mail,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them. They must already exist.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// `mail` (#63) sends the link to the address on the person's entry through
        /// the realm's mail transport and does NOT return it: the answer carries
        /// `mailedTo`. If it cannot be mailed the link is returned as with `show`
        /// (the default), with `mailError` saying why.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliver: Option<BodyDeliver>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors17;
}

/// Revoke somebody's password and issue a one-time reset link
pub mod issue_password_reset_link {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/issue-password-reset";
    pub const OPERATION_ID: &str = "issuePasswordResetLink";

    /// `mail` (#63) sends the link to the address on the person's entry through the
    /// realm's mail transport and does NOT return it: the answer carries
    /// `mailedTo`. If it cannot be mailed the link is returned as with `show` (the
    /// default), with `mailError` saying why.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDeliver {
        #[serde(rename = "show")]
        Show,
        #[serde(rename = "mail")]
        Mail,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The reset is BECAUSE a credential was compromised: RISC
        /// `credential-compromise` (`password`) is sent as well (#146).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compromised: Option<bool>,
        /// `mail` (#63) sends the link to the address on the person's entry through
        /// the realm's mail transport and does NOT return it: the answer carries
        /// `mailedTo`. If it cannot be mailed the link is returned as with `show`
        /// (the default), with `mailError` saying why.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliver: Option<BodyDeliver>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors26;
}

/// Issue somebody a message-signing certificate from this realm's CA
pub mod issue_user_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/issue-signing-certificate";
    pub const OPERATION_ID: &str = "issueUserSigningCertificate";

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
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors39;
}

/// Every attribute a person may be created with, and the four ways they can be
/// given a way in
pub mod get_new_user_form {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/new";
    pub const OPERATION_ID: &str = "getNewUserForm";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub invent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::NewUserForm;
}

/// Prove possession of a person's classical passkey
pub mod prove_user_passkey_upgrade {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/prove-passkey-upgrade";
    pub const OPERATION_ID: &str = "proveUserPasskeyUpgrade";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub user: String,
        #[serde(rename = "upgradeId")]
        pub upgrade_id: String,
        pub credential: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors50;
}

/// The did:web DIDs this realm publishes for one person
pub mod get_user_published_dids {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/published-dids";
    pub const OPERATION_ID: &str = "getUserPublishedDids";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        pub user: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DidsItemDeactivatedV1 {
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
    pub enum Answer200DidsItemDeactivated {
        V1(Answer200DidsItemDeactivatedV1),
        Bool(bool),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DidsItemPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub change: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DidsItemVersionsItemKeysItem {
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
    pub struct Answer200DidsItemVersionsItemAuthorizedByItem {
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
    pub struct Answer200DidsItemVersionsItem {
        #[serde(rename = "versionId", default, skip_serializing_if = "Option::is_none")]
        pub version_id: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub change: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200DidsItemVersionsItemKeysItem>>,
        #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
        pub authorized_by: Option<Vec<Answer200DidsItemVersionsItemAuthorizedByItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DidsItem {
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
        pub deactivated: Option<Option<Answer200DidsItemDeactivated>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proof: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preferred: Option<bool>,
        #[serde(rename = "currentVersion", default, skip_serializing_if = "Option::is_none")]
        pub current_version: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Answer200DidsItemPending>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub versions: Option<Vec<Answer200DidsItemVersionsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
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
        pub dids: Option<Vec<Answer200DidsItem>>,
    }
}

/// Record an identity verification for somebody
pub mod record_user_verification {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/record-verification";
    pub const OPERATION_ID: &str = "recordUserVerification";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyClaimsItem {
        #[serde(rename = "name")]
        Name,
        #[serde(rename = "given_name")]
        GivenName,
        #[serde(rename = "family_name")]
        FamilyName,
        #[serde(rename = "middle_name")]
        MiddleName,
        #[serde(rename = "birthdate")]
        Birthdate,
        #[serde(rename = "gender")]
        Gender,
        #[serde(rename = "address")]
        Address,
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "phone_number")]
        PhoneNumber,
        #[serde(rename = "place_of_birth")]
        PlaceOfBirth,
        #[serde(rename = "nationalities")]
        Nationalities,
        #[serde(rename = "birth_family_name")]
        BirthFamilyName,
        #[serde(rename = "birth_given_name")]
        BirthGivenName,
        #[serde(rename = "birth_middle_name")]
        BirthMiddleName,
        #[serde(rename = "salutation")]
        Salutation,
        #[serde(rename = "title")]
        Title,
        #[serde(rename = "msisdn")]
        Msisdn,
        #[serde(rename = "also_known_as")]
        AlsoKnownAs,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The verification element (Identity Assurance section 5.1).
        pub verification: serde_json::Map<String, serde_json::Value>,
        /// The claims it covered, from claims_in_verified_claims_supported.
        pub claims: Vec<BodyClaimsItem>,
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors44;
}

/// Remove one value from one of somebody's attributes
pub mod remove_user_attribute_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/remove-attribute";
    pub const OPERATION_ID: &str = "removeUserAttributeValue";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The attribute, as `attributeEditor.attributes[].name` in GET
        /// /admin-api/users?user= names it.
        pub attribute: String,
        /// The value to remove.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors23;
}

/// Take a stored certificate off somebody's entry
pub mod remove_user_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/remove-certificate";
    pub const OPERATION_ID: &str = "removeUserCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The SHA-256 of the certificate's DER, hex.
        pub sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors38;
}

/// Remove one of somebody's devices
pub mod remove_user_device {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/remove-device";
    pub const OPERATION_ID: &str = "removeUserDevice";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The device's id, from GET /admin-api/users/devices.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors37;
}

/// Remove one of somebody's self-issued subjects
pub mod remove_user_self_issued_subject {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/remove-self-issued-subject";
    pub const OPERATION_ID: &str = "removeUserSelfIssuedSubject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The subject, as listed.
        pub subject: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors37;
}

/// Take one owner off a service account
pub mod remove_service_account_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/remove-service-account-owner";
    pub const OPERATION_ID: &str = "removeServiceAccountOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service account, as /admin-api/users names it.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The owner's DN.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors31;
}

/// Remove one of somebody's identity verifications
pub mod remove_user_verification {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/remove-verification";
    pub const OPERATION_ID: &str = "removeUserVerification";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The verification's id, from GET /admin-api/users/verifications.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors37;
}

/// Rename one of somebody's passkeys
pub mod rename_user_passkey {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/rename-key";
    pub const OPERATION_ID: &str = "renameUserPasskey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// base64url, as WebAuthn produced it.
        #[serde(rename = "credentialId")]
        pub credential_id: String,
        /// The new name; empty restores the default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
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
        pub label: Option<String>,
    }
}

/// Require somebody to sign in with a second factor
pub mod require_user_second_factor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/require-mfa";
    pub const OPERATION_ID: &str = "requireUserSecondFactor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors29;
}

/// Reset somebody's password to a generated one, returned once
pub mod reset_user_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/reset-password";
    pub const OPERATION_ID: &str = "resetUserPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The reset is BECAUSE a credential was compromised: RISC
        /// `credential-compromise` (`password`) is sent as well (#146).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compromised: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors25;
}

/// Revoke one of somebody's app passwords
pub mod revoke_user_app_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/revoke-app-password";
    pub const OPERATION_ID: &str = "revokeUserAppPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The app password's public id.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors48;
}

/// Revoke one of somebody's message-signing certificates
pub mod revoke_user_signing_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/revoke-signing-certificate";
    pub const OPERATION_ID: &str = "revokeUserSigningCertificate";

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
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors40;
}

/// Rotate a service account's password now
pub mod rotate_service_account_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/rotate-password";
    pub const OPERATION_ID: &str = "rotateServiceAccountPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service account, as /admin-api/users names it.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors32;
}

/// The self-issued (SIOPv2) subjects enrolled for one person
pub mod get_user_self_issued_subjects {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/self-issued-subjects";
    pub const OPERATION_ID: &str = "getUserSelfIssuedSubjects";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        pub user: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
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
        pub subjects: Option<Vec<sts_model_management_components_4::WithSubjectLabelEnrolledAt2>>,
    }
}

/// Replace every value of one of somebody's attributes
pub mod set_user_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-attribute";
    pub const OPERATION_ID: &str = "setUserAttribute";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The attribute, as `attributeEditor.attributes[].name` in GET
        /// /admin-api/users?user= names it.
        pub attribute: String,
        /// The one value it will hold; empty removes it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors23;
}

/// Record the account id a client knows somebody by
pub mod set_user_aud_sub {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-aud-sub";
    pub const OPERATION_ID: &str = "setUserAudSub";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The client_id.
        pub client: String,
        /// The aud_sub; empty removes it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
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

/// Set the delegation semantics a person allows
pub mod set_user_delegation_semantics {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-delegation-semantics";
    pub const OPERATION_ID: &str = "setUserDelegationSemantics";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySemanticsV1Item {
        #[serde(rename = "delegation")]
        Delegation,
        #[serde(rename = "impersonation")]
        Impersonation,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodySemantics {
        V1(Vec<BodySemanticsV1Item>),
        String(String),
    }

    /// The default; left out, it is cleared.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDefault {
        #[serde(rename = "delegation")]
        Delegation,
        #[serde(rename = "impersonation")]
        Impersonation,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// delegation and/or impersonation, as a list or comma separated; empty
        /// clears.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub semantics: Option<BodySemantics>,
        /// The default; left out, it is cleared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub default: Option<BodyDefault>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors35;
}

/// Set somebody's email address
pub mod set_user_mail {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-mail";
    pub const OPERATION_ID: &str = "setUserMail";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The address.
        pub mail: String,
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
        pub mail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
    }
}

/// Name the one party who may act for somebody
pub mod set_user_may_act {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-may-act";
    pub const OPERATION_ID: &str = "setUserMayAct";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The DN of the person or application; empty clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegate: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors34;
}

/// Mark somebody as one who cannot be delegated
pub mod set_user_not_delegated {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-not-delegated";
    pub const OPERATION_ID: &str = "setUserNotDelegated";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// true sets the flag (the default), false clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors33;
}

/// Set or replace somebody's password
pub mod set_user_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-password";
    pub const OPERATION_ID: &str = "setUserPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them. They must already exist.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The password to set. Required unless `generate` is true.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// Optional, checked where sent.
        #[serde(rename = "passwordConfirm", default, skip_serializing_if = "Option::is_none")]
        pub password_confirm: Option<String>,
        /// Make one up instead — 32 bytes of randomBytes, base64url, the same
        /// generator the product-mode bootstrap account uses. It is RETURNED ONCE
        /// in `password` and never again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generate: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors19;
}

/// Mark one of somebody's proved DIDs as their preferred one, or clear the mark
pub mod set_user_preferred_self_issued_subject {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-preferred-self-issued-subject";
    pub const OPERATION_ID: &str = "setUserPreferredSelfIssuedSubject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The DID, as listed; empty or absent clears the mark.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors42;
}

/// Add or remove one of somebody's sign-in names
pub mod set_user_pseudonyms {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-pseudonyms";
    pub const OPERATION_ID: &str = "setUserPseudonyms";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// A name to add.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub add: Option<String>,
        /// A live name to remove.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remove: Option<String>,
        /// True cancels a name waiting for its link.
        #[serde(rename = "cancelPending", default, skip_serializing_if = "Option::is_none")]
        pub cancel_pending: Option<sts_model_base::unions::BoolOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors22;
}

/// Make somebody a service account, or a person again
pub mod set_user_service_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-service-account";
    pub const OPERATION_ID: &str = "setUserServiceAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// true makes or keeps them a service account (the default); false makes
        /// them a person again.
        #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
        pub service_account: Option<bool>,
        /// The people and groups answerable for the account (#600), each a DN, a
        /// username or a group's cn: an array, or a string of one per line. It
        /// REPLACES the owners the account names; absent or empty is none, refused
        /// while the policy requires an owner.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<sts_model_base::unions::StringOrList>,
        /// The DN of the push destination (an application entry).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination: Option<String>,
        /// The secret's name or path at the destination; it must already exist
        /// there.
        #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none")]
        pub secret_name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors30;
}

/// Set or clear a service account's push destination
pub mod set_service_account_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/set-service-account-destination";
    pub const OPERATION_ID: &str = "setServiceAccountDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service account, as /admin-api/users names it.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// The destination's DN, or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination: Option<String>,
        /// The secret's name or path there, or empty.
        #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none")]
        pub secret_name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors31;
}

/// Take the per-account second-factor requirement off
pub mod stop_requiring_user_second_factor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/stop-requiring-mfa";
    pub const OPERATION_ID: &str = "stopRequiringUserSecondFactor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors29;
}

/// Set several of somebody's attributes at once
pub mod update_user_fields {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/users/update-fields";
    pub const OPERATION_ID: &str = "updateUserFields";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as /admin-api/users names them.
        pub user: String,
        /// Accepted for `user`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// Attribute name to a string or an array of strings; empty clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
        /// The fields the console's form drew, by attribute name, space or comma
        /// separated or as a list: each one is cleared when the form carries no
        /// value for it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<sts_model_base::unions::StringOrList>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors24;
}

/// One person's identity verifications (OpenID Connect for Identity Assurance)
pub mod get_user_verifications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/users/verifications";
    pub const OPERATION_ID: &str = "getUserVerifications";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        pub user: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
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
        pub verifications: Option<Vec<sts_model_management_components_4::WithIdRecordedSource>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }
}

/// A verification's outcome, or the verifications still open
pub mod get_verifications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/verifications";
    pub const OPERATION_ID: &str = "getVerifications";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictChecksItemDetail {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200VerdictChecksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub detail: Option<Option<Answer200VerdictChecksItemDetail>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictDisclosedItem {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictExtraDisclosedItem {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictVct {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictSub {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictPresentationDigest {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200VerdictSelfIssuedSubject {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200VerdictSelfIssued {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<Answer200VerdictSelfIssuedSubject>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<sts_model_management_components_2::HolderSWalletDisclosedCredential>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Verdict {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(rename = "errorDescription", default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checks: Option<Vec<Answer200VerdictChecksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<sts_model_management_components_2::HolderSWalletDisclosedCredential>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disclosed: Option<Vec<Option<Answer200VerdictDisclosedItem>>>,
        #[serde(rename = "extraDisclosed", default, skip_serializing_if = "Option::is_none")]
        pub extra_disclosed: Option<Vec<Option<Answer200VerdictExtraDisclosedItem>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requested: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub vct: Option<Option<Answer200VerdictVct>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sub: Option<Option<Answer200VerdictSub>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(rename = "presentationDigest", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub presentation_digest: Option<Option<Answer200VerdictPresentationDigest>>,
        #[serde(rename = "selfIssued", default, skip_serializing_if = "Option::is_none")]
        pub self_issued: Option<Answer200VerdictSelfIssued>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verifications: Option<sts_model_management_components_4::WithOkMessageErrors76>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nonce: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requested: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dcql_query: Option<sts_model_management_components_4::WithCredentialsCredentialsetsState2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub received: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<Answer200Verdict>,
    }
}

/// Start an OpenID4VP verification: build a request for a wallet
pub mod start_verification {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/verifications/start";
    pub const OPERATION_ID: &str = "startVerification";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyBy {
        #[serde(rename = "value")]
        Value,
        #[serde(rename = "reference")]
        Reference,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyClientIdPrefix {
        #[serde(rename = "pre-registered")]
        PreRegistered,
        #[serde(rename = "decentralized_identifier")]
        DecentralizedIdentifier,
        #[serde(rename = "verifier_attestation")]
        VerifierAttestation,
        #[serde(rename = "openid_federation")]
        OpenidFederation,
        #[serde(rename = "x509_san_dns")]
        X509SanDns,
        #[serde(rename = "x509_hash")]
        X509Hash,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyResponseType {
        #[serde(rename = "vp_token")]
        VpToken,
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "vp_token id_token")]
        VpTokenIdToken,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyResponseMode {
        #[serde(rename = "direct_post")]
        DirectPost,
        #[serde(rename = "direct_post.jwt")]
        DirectPostJwt,
        #[serde(rename = "form_post")]
        FormPost,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMode {
        #[serde(rename = "same-device")]
        SameDevice,
        #[serde(rename = "cross-device")]
        CrossDevice,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A format id: dc+sd-jwt, jwt_vc_json, ldp_vc, mso_mdoc. Not a closed set
        /// here, as on `/verifier-request/format`: a form-encoded `+` arrives as a
        /// space and is put back, and the Verifier refuses anything else by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub by: Option<BodyBy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id_prefix: Option<BodyClientIdPrefix>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_type: Option<BodyResponseType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_mode: Option<BodyResponseMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<BodyMode>,
        /// A web wallet to send the holder to, if not `oid4vp.walletUrl` or a
        /// wallet app (the default).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<String>,
        /// The caller's page the wallet is sent to once the Verifier has answered
        /// (#594); a registered redirect URI of the calling client wherever only
        /// registered addresses are accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub redirect_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors78;
}

/// What this realm's OID4VP Verifier asks a wallet for
pub mod get_verifier_request {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/verifier-request";
    pub const OPERATION_ID: &str = "getVerifierRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200FormatsItemIdentifier {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormatsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "identifiedBy", default, skip_serializing_if = "Option::is_none")]
        pub identified_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<Answer200FormatsItemIdentifier>,
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
    pub struct Answer200CatalogueItemAttributesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ldap: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CatalogueItemIssued {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub carried: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CatalogueItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nested: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<Answer200CatalogueItemAttributesItem>>,
        #[serde(rename = "ldpTerms", default, skip_serializing_if = "Option::is_none")]
        pub ldp_terms: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<Vec<Vec<String>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requested: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Answer200CatalogueItemIssued>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ExtrasItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<Vec<Vec<String>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RecentVerifications {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verifications: Option<sts_model_management_components_4::WithOkMessageErrors76>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StartChoices {
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
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requested: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub formats: Option<Vec<Answer200FormatsItem>>,
        #[serde(rename = "ldpOmitted", default, skip_serializing_if = "Option::is_none")]
        pub ldp_omitted: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogue: Option<Vec<Answer200CatalogueItem>>,
        #[serde(rename = "dcqlQuery", default, skip_serializing_if = "Option::is_none")]
        pub dcql_query: Option<sts_model_management_components_4::WithCredentialsCredentialsetsState2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub extras: Option<Vec<Answer200ExtrasItem>>,
        #[serde(rename = "recentVerifications", default, skip_serializing_if = "Option::is_none")]
        pub recent_verifications: Option<Answer200RecentVerifications>,
        #[serde(rename = "startChoices", default, skip_serializing_if = "Option::is_none")]
        pub start_choices: Option<Answer200StartChoices>,
    }
}

/// Ask for one more claim
pub mod add_requested_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/verifier-request/add";
    pub const OPERATION_ID: &str = "addRequestedClaim";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        /// An alias for `claim`; `vpConfigAction()` reads `body.claim ||
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors77;
}

/// Back to what this process started with
pub mod reset_requested_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/verifier-request/defaults";
    pub const OPERATION_ID: &str = "resetRequestedClaims";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors77;
}

/// Set the credential format a request asks in
pub mod set_request_format {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/verifier-request/format";
    pub const OPERATION_ID: &str = "setRequestFormat";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A format id. `GET /admin-api/verifier-request` lists them under
        /// `formats`.
        pub format: String,
        /// An alias for `claim`; `vpConfigAction()` reads `body.claim ||
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors77;
}

/// Stop asking for one claim
pub mod remove_requested_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/verifier-request/remove";
    pub const OPERATION_ID: &str = "removeRequestedClaim";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        /// An alias for `claim`; `vpConfigAction()` reads `body.claim ||
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors77;
}

/// Set the whole list of requested claims
pub mod select_requested_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/verifier-request/select";
    pub const OPERATION_ID: &str = "selectRequestedClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Top-level claim names. A credential carries one Disclosure per top-level
        /// claim, so `address` is one unit however many attributes feed it.
        pub claims: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors77;
}

/// The security-key ceremony's settings, and what a key may be here
pub mod get_webauthn_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/webauthn";
    pub const OPERATION_ID: &str = "getWebauthnSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LinksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<Answer200LinksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue>,
        #[serde(rename = "leadHtml", default, skip_serializing_if = "Option::is_none")]
        pub lead_html: Option<String>,
        #[serde(rename = "alsoHtml", default, skip_serializing_if = "Option::is_none")]
        pub also_html: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<sts_model_management_components_4::WithOfferedRpNameRpId>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// The passive requestor profile's page
pub mod get_ws_fed_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/wsfed";
    pub const OPERATION_ID: &str = "getWsFedSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat2;
}

/// The security token service's own settings
pub mod get_ws_trust_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/wstrust";
    pub const OPERATION_ID: &str = "getWsTrustSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat2;
}

/// The Policy Decision Point settings and current status
pub mod get_xacml {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml";
    pub const OPERATION_ID: &str = "getXacml";

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
        pub settings: Option<sts_model_management_components_3::SettingsValue3>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Add an alternative to a Target clause
pub mod add_xacml_alternative {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-allof";
    pub const OPERATION_ID: &str = "addXacmlAlternative";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The match function. Defaults to string-equal. THE DATATYPE FOLLOWS IT on
        /// both sides, so choosing the function settles the literal's type and the
        /// designator's together.
        #[serde(rename = "matchId", default, skip_serializing_if = "Option::is_none")]
        pub match_id: Option<String>,
        /// The literal to test against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// The attribute category. Defaults to access-subject.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// The attribute to read. A bare name or the `urn:sts:xacml:attribute:`
        /// prefix reaches the directory through the PIP; anything else must be in
        /// the request.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add an argument to a function call
pub mod add_xacml_argument {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-argument";
    pub const OPERATION_ID: &str = "addXacmlArgument";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add an attribute assignment to an obligation or advice
pub mod add_xacml_assignment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-assignment";
    pub const OPERATION_ID: &str = "addXacmlAssignment";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a Condition to a rule
pub mod add_xacml_condition {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-condition";
    pub const OPERATION_ID: &str = "addXacmlCondition";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a Match to an alternative
pub mod add_xacml_match {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-match";
    pub const OPERATION_ID: &str = "addXacmlMatch";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The match function. Defaults to string-equal. THE DATATYPE FOLLOWS IT on
        /// both sides, so choosing the function settles the literal's type and the
        /// designator's together.
        #[serde(rename = "matchId", default, skip_serializing_if = "Option::is_none")]
        pub match_id: Option<String>,
        /// The literal to test against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// The attribute category. Defaults to access-subject.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// The attribute to read. A bare name or the `urn:sts:xacml:attribute:`
        /// prefix reaches the directory through the PIP; anything else must be in
        /// the request.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a Policy inside a PolicySet
pub mod add_xacml_policy_to_set {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-policy";
    pub const OPERATION_ID: &str = "addXacmlPolicyToSet";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add advice to a policy
pub mod add_xacml_policy_advice {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-policy-advice";
    pub const OPERATION_ID: &str = "addXacmlPolicyAdvice";

    /// Permit or Deny. Defaults to Permit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOn {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// Permit or Deny. Defaults to Permit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<BodyOn>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add an obligation to a policy
pub mod add_xacml_policy_obligation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-policy-obligation";
    pub const OPERATION_ID: &str = "addXacmlPolicyObligation";

    /// Permit or Deny. Defaults to Permit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOn {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// Permit or Deny. Defaults to Permit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<BodyOn>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Reference a policy stored separately in the repository
pub mod add_xacml_policy_reference {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-policy-reference";
    pub const OPERATION_ID: &str = "addXacmlPolicyReference";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The PolicyId being referenced. Any URI.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        pub ref_: Option<String>,
        /// An optional version constraint. Omit for no constraint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a nested PolicySet inside a PolicySet
pub mod add_xacml_policy_set_to_set {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-policyset";
    pub const OPERATION_ID: &str = "addXacmlPolicySetToSet";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Reference a policy SET stored separately
pub mod add_xacml_policy_set_reference {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-policyset-reference";
    pub const OPERATION_ID: &str = "addXacmlPolicySetReference";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The PolicySetId being referenced.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        pub ref_: Option<String>,
        /// An optional version constraint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a rule to a policy
pub mod add_xacml_rule {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-rule";
    pub const OPERATION_ID: &str = "addXacmlRule";

    /// Permit or Deny. Defaults to Permit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyEffect {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// Permit or Deny. Defaults to Permit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub effect: Option<BodyEffect>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add advice to a rule
pub mod add_xacml_rule_advice {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-rule-advice";
    pub const OPERATION_ID: &str = "addXacmlRuleAdvice";

    /// Permit or Deny. Defaults to Permit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOn {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// Permit or Deny. Defaults to Permit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<BodyOn>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add an obligation to a rule
pub mod add_xacml_rule_obligation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-rule-obligation";
    pub const OPERATION_ID: &str = "addXacmlRuleObligation";

    /// Permit or Deny — the effect this fires on. Defaults to Permit. An obligation
    /// attached to the wrong effect is silently never discharged.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOn {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// Permit or Deny — the effect this fires on. Defaults to Permit. An
        /// obligation attached to the wrong effect is silently never discharged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<BodyOn>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a Target clause to a policy, a rule or a Target
pub mod add_xacml_target_clause {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-target-anyof";
    pub const OPERATION_ID: &str = "addXacmlTargetClause";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// The match function. Defaults to string-equal. THE DATATYPE FOLLOWS IT on
        /// both sides, so choosing the function settles the literal's type and the
        /// designator's together.
        #[serde(rename = "matchId", default, skip_serializing_if = "Option::is_none")]
        pub match_id: Option<String>,
        /// The literal to test against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// The attribute category. Defaults to access-subject.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// The attribute to read. A bare name or the `urn:sts:xacml:attribute:`
        /// prefix reaches the directory through the PIP; anything else must be in
        /// the request.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Add a VariableDefinition to a policy
pub mod add_xacml_variable {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/add-variable";
    pub const OPERATION_ID: &str = "addXacmlVariable";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The name. Defaults to the next free `v<n>`. A duplicate is refused — the
        /// reader rejects a document defining one id twice, so allowing it here
        /// would write a policy this service cannot load back.
        #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
        pub variable_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// The AuthZEN API: its settings, attribute catalogue and callers
pub mod get_xacml_authzen {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml/authzen";
    pub const OPERATION_ID: &str = "getXacmlAuthzen";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub caller: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Catalogue {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<sts_model_management_components_4::WithKeyObjectProperty>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problems: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub objects: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub categories: Option<Vec<String>>,
        #[serde(rename = "dataTypes", default, skip_serializing_if = "Option::is_none")]
        pub data_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multiplicities: Option<Vec<String>>,
        #[serde(rename = "reservedPrefix", default, skip_serializing_if = "Option::is_none")]
        pub reserved_prefix: Option<String>,
        #[serde(rename = "reservedContext", default, skip_serializing_if = "Option::is_none")]
        pub reserved_context: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Looked {
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

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AccessRequests {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<sts_model_management_components_4::WithIdStatusRequester>>,
        #[serde(rename = "maxCallbacks", default, skip_serializing_if = "Option::is_none")]
        pub max_callbacks: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "xacmlEnabled", default, skip_serializing_if = "Option::is_none")]
        pub xacml_enabled: Option<bool>,
        #[serde(rename = "apiObject", default, skip_serializing_if = "Option::is_none")]
        pub api_object: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<Vec<String>>,
        #[serde(rename = "callerAuthentication", default, skip_serializing_if = "Option::is_none")]
        pub caller_authentication: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue3>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogue: Option<Answer200Catalogue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub callers: Option<Vec<sts_model_management_components_4::WithDnNameKind>>,
        #[serde(rename = "callersTotal", default, skip_serializing_if = "Option::is_none")]
        pub callers_total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looked: Option<Answer200Looked>,
        #[serde(rename = "accessRequests", default, skip_serializing_if = "Option::is_none")]
        pub access_requests: Option<Answer200AccessRequests>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Approve an AuthZEN access request
pub mod approve_authzen_access_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/approve-access-request";
    pub const OPERATION_ID: &str = "approveAuthzenAccessRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The access request's id (arq_...).
        pub request: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors180;
}

/// Cancel an AuthZEN access request
pub mod cancel_authzen_access_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/cancel-access-request";
    pub const OPERATION_ID: &str = "cancelAuthzenAccessRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The access request's id (arq_...).
        pub request: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors180;
}

/// Deny an AuthZEN access request
pub mod deny_authzen_access_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/deny-access-request";
    pub const OPERATION_ID: &str = "denyAuthzenAccessRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The access request's id (arq_...).
        pub request: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors180;
}

/// Remove one row of the AuthZEN attribute catalogue
pub mod remove_authzen_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/remove-attribute";
    pub const OPERATION_ID: &str = "removeAuthzenAttribute";

    /// The AuthZEN object the property is on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyObject {
        #[serde(rename = "subject")]
        Subject,
        #[serde(rename = "resource")]
        Resource,
        #[serde(rename = "action")]
        Action,
        #[serde(rename = "context")]
        Context,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The AuthZEN object the property is on.
        pub object: BodyObject,
        /// The property's name, or a dotted path into a nested object
        /// (owner.country). For context, the member's name; context.application is
        /// reserved.
        pub property: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors178;
}

/// Revoke an AuthZEN access request's approval
pub mod revoke_authzen_access_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/revoke-access-request";
    pub const OPERATION_ID: &str = "revokeAuthzenAccessRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The access request's id (arq_...).
        pub request: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors180;
}

/// Add or replace one row of the AuthZEN attribute catalogue
pub mod set_authzen_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/set-attribute";
    pub const OPERATION_ID: &str = "setAuthzenAttribute";

    /// The AuthZEN object the property is on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyObject {
        #[serde(rename = "subject")]
        Subject,
        #[serde(rename = "resource")]
        Resource,
        #[serde(rename = "action")]
        Action,
        #[serde(rename = "context")]
        Context,
    }

    /// single (one value) or bag (a JSON array); single when left out.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMultiplicity {
        #[serde(rename = "single")]
        Single,
        #[serde(rename = "bag")]
        Bag,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The AuthZEN object the property is on.
        pub object: BodyObject,
        /// The property's name, or a dotted path into a nested object
        /// (owner.country). For context, the member's name; context.application is
        /// reserved.
        pub property: String,
        /// The XACML attribute it is sent as. Never urn:sts:xacml:*, subject-id,
        /// resource-id or action-id, nor a bare directory name in a subject
        /// category.
        #[serde(rename = "attributeId")]
        pub attribute_id: String,
        /// access-subject, resource, action, environment (or another XACML
        /// category, or its URI); the object's own when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// string, boolean, integer, double, date, dateTime, time, anyURI,
        /// dayTimeDuration, yearMonthDuration, hexBinary, base64Binary, rfc822Name,
        /// x500Name, dnsName, ipAddress, or the type's URI; string when empty.
        #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
        pub data_type: Option<String>,
        /// single (one value) or bag (a JSON array); single when left out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multiplicity: Option<BodyMultiplicity>,
        /// Free text for administrators.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors178;
}

/// Set the access request callback URLs of an AuthZEN caller
pub mod set_authzen_callbacks {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/set-callbacks";
    pub const OPERATION_ID: &str = "setAuthzenCallbacks";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyCallbacks {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A username, an application identifier, or a DN.
        pub caller: String,
        /// The URLs, as a list or as one string separated by commas or spaces.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub callbacks: Option<BodyCallbacks>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors179;
}

/// Set the applications an AuthZEN caller may ask about
pub mod set_authzen_scope {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/authzen/set-scope";
    pub const OPERATION_ID: &str = "setAuthzenScope";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyApplications {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A username, an application identifier, or a DN.
        pub caller: String,
        /// The applications, as a list or as one string separated by commas or
        /// spaces.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<BodyApplications>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors179;
}

/// Create a policy from a template
pub mod create_xacml_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/create-from-template";
    pub const OPERATION_ID: &str = "createXacmlPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Body {
        /// Which template. GET /admin-api/xacml/policies lists them with the
        /// parameters each takes.
        pub template: String,
        /// Names the DIRECTORY ENTRY. The PolicyId inside the document is a
        /// separate identifier and may be any URI.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Ask the PDP about somebody and see the decision, which policies applied, and
/// what the embedded PEP would do with it
pub mod get_xacml_decision {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml/decide";
    pub const OPERATION_ID: &str = "getXacmlDecision";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StatusDetail {
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
    pub struct Answer200Status {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub message: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<Answer200StatusDetail>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicablePoliciesItemV1 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200ApplicablePoliciesItem {
        V1(Answer200ApplicablePoliciesItemV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Enforcement {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bias: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnforcementsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bias: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
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
        pub status: Option<Answer200Status>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub obligations: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub advice: Option<Vec<String>>,
        #[serde(rename = "applicablePolicies", default, skip_serializing_if = "Option::is_none")]
        pub applicable_policies: Option<Vec<Answer200ApplicablePoliciesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforcement: Option<Answer200Enforcement>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforcements: Option<Vec<Answer200EnforcementsItem>>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Remove a policy from the repository
pub mod delete_xacml_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/delete";
    pub const OPERATION_ID: &str = "deleteXacmlPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policy's directory entry name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Take a policy out of the decision without deleting it
pub mod disable_xacml_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/disable";
    pub const OPERATION_ID: &str = "disableXacmlPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policy's directory entry name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Stop nudging a registered remote PEP
pub mod disable_xacml_pep {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/disable-pep";
    pub const OPERATION_ID: &str = "disableXacmlPep";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The registered PEP's name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change which function a call applies
pub mod edit_xacml_apply {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-apply";
    pub const OPERATION_ID: &str = "editXacmlApply";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The function to apply instead. The arguments are reshaped to the new
        /// signature.
        #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
        pub function_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change an attribute assignment's id, category or issuer
pub mod edit_xacml_assignment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-assignment";
    pub const OPERATION_ID: &str = "editXacmlAssignment";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The name the PEP receives it under.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
        /// An optional category. Empty removes it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// An optional issuer. Empty removes it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change an attribute reference
pub mod edit_xacml_designator {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-designator";
    pub const OPERATION_ID: &str = "editXacmlDesignator";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// A new category.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// A new attribute id.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
        /// A new datatype URI.
        #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
        pub data_type: Option<String>,
        /// False makes an absent attribute an empty bag; true makes the whole
        /// expression Indeterminate, which the combining algorithms treat quite
        /// differently from a Deny.
        #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
        pub must_be_present: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change which function a Function reference names
pub mod edit_xacml_function_reference {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-function";
    pub const OPERATION_ID: &str = "editXacmlFunctionReference";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// Any identifier in the function library.
        #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
        pub function_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change a Match's function, value or attribute
pub mod edit_xacml_match {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-match";
    pub const OPERATION_ID: &str = "editXacmlMatch";

    /// Whether the Match names its attribute by an AttributeDesignator (the
    /// default) or reads it with an AttributeSelector's XPath `path`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReferenceKind {
        #[serde(rename = "designator")]
        Designator,
        #[serde(rename = "selector")]
        Selector,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The match function. Defaults to string-equal. THE DATATYPE FOLLOWS IT on
        /// both sides, so choosing the function settles the literal's type and the
        /// designator's together.
        #[serde(rename = "matchId", default, skip_serializing_if = "Option::is_none")]
        pub match_id: Option<String>,
        /// The literal to test against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        /// The attribute category. Defaults to access-subject.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// The attribute to read. A bare name or the `urn:sts:xacml:attribute:`
        /// prefix reaches the directory through the PIP; anything else must be in
        /// the request.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
        /// Whether an absent attribute is an empty bag (false) or makes the whole
        /// expression Indeterminate (true).
        #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
        pub must_be_present: Option<bool>,
        /// Whether the Match names its attribute by an AttributeDesignator (the
        /// default) or reads it with an AttributeSelector's XPath `path`.
        #[serde(rename = "referenceKind", default, skip_serializing_if = "Option::is_none")]
        pub reference_kind: Option<BodyReferenceKind>,
        /// A selector's ContextSelectorId.
        #[serde(rename = "contextSelectorId", default, skip_serializing_if = "Option::is_none")]
        pub context_selector_id: Option<String>,
        /// A designator's Issuer; empty clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change an obligation's or advice's id, or when it fires
pub mod edit_xacml_obligation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-obligation";
    pub const OPERATION_ID: &str = "editXacmlObligation";

    /// Permit or Deny — the effect it fires on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOn {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// A new obligation or advice identifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// Permit or Deny — the effect it fires on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<BodyOn>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change a policy's id, description or combining algorithm
pub mod edit_xacml_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-policy";
    pub const OPERATION_ID: &str = "editXacmlPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// A new PolicySetId or PolicyId. Any URI.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// The document's own <Description>.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// The document's Version: dot-separated numbers, "1" or "1.0". Empty
        /// leaves it as it is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        /// One of the rule-combining algorithms this editor offers; anything else
        /// is refused rather than written. THE SINGLE MOST CONSEQUENTIAL LINE IN A
        /// POLICY.
        #[serde(rename = "combiningAlgId", default, skip_serializing_if = "Option::is_none")]
        pub combining_alg_id: Option<String>,
        /// The document's <MaxDelegationDepth>: a non-negative integer, or empty
        /// for none.
        #[serde(rename = "maxDelegationDepth", default, skip_serializing_if = "Option::is_none")]
        pub max_delegation_depth: Option<String>,
        /// The document's <XPathVersion> in its defaults, a URI; empty removes it.
        #[serde(rename = "xpathVersion", default, skip_serializing_if = "Option::is_none")]
        pub xpath_version: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change what a policy reference names
pub mod edit_xacml_reference {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-reference";
    pub const OPERATION_ID: &str = "editXacmlReference";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The PolicyId or PolicySetId to name.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        pub ref_: Option<String>,
        /// A version constraint, or empty for none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change a rule's id, effect or description
pub mod edit_xacml_rule {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-rule";
    pub const OPERATION_ID: &str = "editXacmlRule";

    /// Permit or Deny.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyEffect {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// A new RuleId.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// Permit or Deny.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub effect: Option<BodyEffect>,
        /// The rule's own description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change an AttributeSelector's path, category or bindings
pub mod edit_xacml_selector {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-selector";
    pub const OPERATION_ID: &str = "editXacmlSelector";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// Sent as `path` collides with the node address; this operation reads the
        /// XPath from `path` ONLY when it is not the address — see the console
        /// form, which posts them separately.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path_xpath: Option<String>,
        /// The category whose content is selected.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// The datatype of the bag it returns.
        #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
        pub data_type: Option<String>,
        /// An attribute naming the starting node, or empty for the whole content.
        #[serde(rename = "contextSelectorId", default, skip_serializing_if = "Option::is_none")]
        pub context_selector_id: Option<String>,
        /// "true" or "false". Absent KEEPS the current value rather than clearing
        /// it.
        #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
        pub must_be_present: Option<String>,
        /// A prefix to bind, rebind or remove.
        #[serde(rename = "namespacePrefix", default, skip_serializing_if = "Option::is_none")]
        pub namespace_prefix: Option<String>,
        /// What to bind it to. Empty removes it.
        #[serde(rename = "namespaceUri", default, skip_serializing_if = "Option::is_none")]
        pub namespace_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Change a literal's datatype or lexical form
pub mod edit_xacml_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-value";
    pub const OPERATION_ID: &str = "editXacmlValue";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// A new datatype URI.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        /// A new lexical form, parsed against that datatype.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lexical: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Rename a variable, and every reference with it
pub mod rename_xacml_variable {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/edit-variable";
    pub const OPERATION_ID: &str = "renameXacmlVariable";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The new name.
        #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
        pub variable_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// One policy as an editable tree, with what may legally be added at each node
pub mod get_xacml_editor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml/editor";
    pub const OPERATION_ID: &str = "getXacmlEditor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Policy {
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
    pub struct Answer200TreeItemOptionsAdditionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub help: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeItemOptions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub additions: Option<Vec<Answer200TreeItemOptionsAdditionsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeItemEditNode {
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
        pub value: Option<sts_model_management_components_4::WithKindTypeLexical2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reference: Option<sts_model_management_components_4::WithKindTypeLexical2>,
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
    pub struct Answer200TreeItemEditAlgorithmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeItemEditScopeItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeItemEdit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node: Option<Answer200TreeItemEditNode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<Answer200TreeItemEditAlgorithmsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<Vec<Answer200TreeItemEditScopeItem>>,
        #[serde(rename = "valueShortType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value_short_type: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeItem {
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
        pub options: Option<Answer200TreeItemOptions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub edit: Option<Answer200TreeItemEdit>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MenusTypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MenusCategoriesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MenusFunctionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MenusMatchFunctionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Menus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub types: Option<Vec<Answer200MenusTypesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub categories: Option<Vec<Answer200MenusCategoriesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub functions: Option<Vec<Answer200MenusFunctionsItem>>,
        #[serde(rename = "matchFunctions", default, skip_serializing_if = "Option::is_none")]
        pub match_functions: Option<Vec<Answer200MenusMatchFunctionsItem>>,
        #[serde(rename = "xpathType", default, skip_serializing_if = "Option::is_none")]
        pub xpath_type: Option<String>,
        #[serde(rename = "resourceCategory", default, skip_serializing_if = "Option::is_none")]
        pub resource_category: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub xacml: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policies: Option<Vec<String>>,
        #[serde(rename = "serviceOwn", default, skip_serializing_if = "Option::is_none")]
        pub service_own: Option<sts_model_management_components_4::WithKindTypeLexical>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Answer200Policy>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub problem: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tree: Option<Vec<Answer200TreeItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub menus: Option<Answer200Menus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problems: Option<Vec<Option<String>>>,
        #[serde(rename = "xpathVersionGaps", default, skip_serializing_if = "Option::is_none")]
        pub xpath_version_gaps: Option<Vec<Option<String>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alfa: Option<Option<String>>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Put a policy back into the decision
pub mod enable_xacml_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/enable";
    pub const OPERATION_ID: &str = "enableXacmlPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policy's directory entry name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Nudge a registered remote PEP again
pub mod enable_xacml_pep {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/enable-pep";
    pub const OPERATION_ID: &str = "enableXacmlPep";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The registered PEP's name, which is the one its client certificate gave
        /// it.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Remove a remote PEP from the register
pub mod forget_xacml_pep {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/forget-pep";
    pub const OPERATION_ID: &str = "forgetXacmlPep";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The registered PEP's name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Create a policy from ALFA
pub mod import_xacml_alfa {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/import-alfa";
    pub const OPERATION_ID: &str = "importXacmlAlfa";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The ALFA source. Parsed, converted and stored as XACML XML — the
        /// repository holds ONE representation.
        pub alfa: String,
        /// Names the directory entry.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Issue a remote PEP the certificate and private key for its HTTPS listener
pub mod issue_xacml_pep_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/issue-pep-certificate";
    pub const OPERATION_ID: &str = "issueXacmlPepCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyDnsNames {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyIpAddresses {
        V1(Vec<String>),
        String(String),
    }

    /// The key algorithm. Defaults to `ec-p256`. Only the RSA and NIST-curve ECDSA
    /// keys a TLS stack serves are offered.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
        #[serde(rename = "ec-p521")]
        EcP521,
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "rsa-4096")]
        Rsa4096,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The registered PEP's name, as GET /admin-api/xacml/peps lists it.
        pub name: String,
        /// DNS names to ADD to the two derived from the registration. An array, or
        /// one string separated by commas or whitespace. A `*.` wildcard is
        /// accepted in the first label.
        #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
        pub dns_names: Option<BodyDnsNames>,
        /// IPv4 or IPv6 addresses to add, in the same two spellings.
        #[serde(rename = "ipAddresses", default, skip_serializing_if = "Option::is_none")]
        pub ip_addresses: Option<BodyIpAddresses>,
        /// The key algorithm. Defaults to `ec-p256`. Only the RSA and NIST-curve
        /// ECDSA keys a TLS stack serves are offered.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        /// The lifetime. Defaults to `pki.leafLifetimeDays`, and is shortened to
        /// the Issuing CA's own expiry.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors108;
}

/// How many authorization decisions are being made, by which enforcement point,
/// and how many are refusals
pub mod get_xacml_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml/monitor";
    pub const OPERATION_ID: &str = "getXacmlMonitor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::XacmlMonitor;
}

/// The REMOTE Policy Enforcement Points that pull this repository, and whether
/// they are deciding with the same policy this service holds
pub mod get_xacml_peps {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml/peps";
    pub const OPERATION_ID: &str = "getXacmlPeps";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NotifyTransport {
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
    pub struct Answer200Notify {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<bool>,
        #[serde(rename = "allowedHosts", default, skip_serializing_if = "Option::is_none")]
        pub allowed_hosts: Option<Vec<String>>,
        #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport: Option<Answer200NotifyTransport>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PepsItemListenerCertificate {
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
    pub struct Answer200PepsItem {
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
        pub listener_certificate: Option<Answer200PepsItemListenerCertificate>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ElsewhereItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListenerCertificates {
        #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none")]
        pub use_case: Option<String>,
        #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithms: Option<Vec<String>>,
        #[serde(rename = "defaultKeyAlg", default, skip_serializing_if = "Option::is_none")]
        pub default_key_alg: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
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
        pub notify: Option<Answer200Notify>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peps: Option<Vec<Answer200PepsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub elsewhere: Option<Vec<Answer200ElsewhereItem>>,
        #[serde(rename = "listenerCertificates", default, skip_serializing_if = "Option::is_none")]
        pub listener_certificates: Option<Answer200ListenerCertificates>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stale: Option<i64>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// The policy repository, with the type-check problems of each
pub mod get_xacml_policies {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/xacml/policies";
    pub const OPERATION_ID: &str = "getXacmlPolicies";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PoliciesItem {
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
    pub struct Answer200ApplicationPoliciesItemPoliciesItem {
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
    pub struct Answer200ApplicationPoliciesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policies: Option<Vec<Answer200ApplicationPoliciesItemPoliciesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TemplatesItemParametersItem {
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
    pub struct Answer200TemplatesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub blurb: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parameters: Option<Vec<Answer200TemplatesItemParametersItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub xacml: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub root: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policies: Option<Vec<Answer200PoliciesItem>>,
        #[serde(rename = "applicationPolicies", default, skip_serializing_if = "Option::is_none")]
        pub application_policies: Option<Vec<Answer200ApplicationPoliciesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub templates: Option<Vec<Answer200TemplatesItem>>,
        #[serde(rename = "serviceOwn", default, skip_serializing_if = "Option::is_none")]
        pub service_own: Option<sts_model_management_components_4::WithKindTypeLexical>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Remove any node from a policy
pub mod remove_xacml_node {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/remove";
    pub const OPERATION_ID: &str = "removeXacmlNode";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Make an expression a function call
pub mod set_xacml_apply {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-expression-apply";
    pub const OPERATION_ID: &str = "setXacmlApply";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The function to apply. Its arguments are PRE-BUILT to the declared arity
        /// and types, so the expression typechecks the moment it exists.
        #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
        pub function_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Make an expression an attribute reference
pub mod set_xacml_designator {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-expression-designator";
    pub const OPERATION_ID: &str = "setXacmlDesignator";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The attribute category. Defaults to access-subject.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// The attribute to read.
        #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
        pub attribute_id: Option<String>,
        /// The datatype URI. Defaults to xs:string.
        #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
        pub data_type: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Replace an expression with a Function reference
pub mod set_xacml_expression_function {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-expression-function";
    pub const OPERATION_ID: &str = "setXacmlExpressionFunction";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The function to name. Defaults to string-equal.
        #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
        pub function_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Replace an expression with an AttributeSelector
pub mod set_xacml_expression_selector {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-expression-selector";
    pub const OPERATION_ID: &str = "setXacmlExpressionSelector";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The request category whose content the path runs over. Defaults to
        /// resource.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        /// Sent as `path` — but `path` is already the node address on this
        /// endpoint, so set the XPath with edit-selector immediately afterwards.
        /// The selector arrives with `//*`, which is complete and valid.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path_xpath: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Make an expression a literal
pub mod set_xacml_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-expression-value";
    pub const OPERATION_ID: &str = "setXacmlValue";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The datatype URI. Defaults to xs:string.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        /// The value, in that datatype's lexical form.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lexical: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Make an expression a variable reference
pub mod set_xacml_variable {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-expression-variable";
    pub const OPERATION_ID: &str = "setXacmlVariable";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The directory entry name of the policy to edit — the `cn` under
        /// ou=policies, not the PolicyId inside the document.
        pub policy: String,
        /// The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST
        /// THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule
        /// 1 now means rule 0.
        pub path: String,
        /// The VariableDefinition to reference. It must exist in the same policy —
        /// the reference is checked at write time.
        #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
        pub variable_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Choose the policy the PDP starts from
pub mod set_xacml_root_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/xacml/set-root";
    pub const OPERATION_ID: &str = "setXacmlRootPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The policy's directory entry name.
        pub name: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors107;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "addUserAttributeValue" => Some(serde_json::from_value::<add_user_attribute_value::Body>(value.clone()).map(|_| ())),
        "addUserCertificate" => Some(serde_json::from_value::<add_user_certificate::Body>(value.clone()).map(|_| ())),
        "addServiceAccountOwner" => Some(serde_json::from_value::<add_service_account_owner::Body>(value.clone()).map(|_| ())),
        "answerUserCibaRequest" => Some(serde_json::from_value::<answer_user_ciba_request::Body>(value.clone()).map(|_| ())),
        "beginUserPasskeyEnrolment" => Some(serde_json::from_value::<begin_user_passkey_enrolment::Body>(value.clone()).map(|_| ())),
        "beginUserPasskeyUpgrade" => Some(serde_json::from_value::<begin_user_passkey_upgrade::Body>(value.clone()).map(|_| ())),
        "cancelUserPasskeyUpgrade" => Some(serde_json::from_value::<cancel_user_passkey_upgrade::Body>(value.clone()).map(|_| ())),
        "clearUserBackupCodes" => Some(serde_json::from_value::<clear_user_backup_codes::Body>(value.clone()).map(|_| ())),
        "clearUserEmailFactor" => Some(serde_json::from_value::<clear_user_email_factor::Body>(value.clone()).map(|_| ())),
        "clearUserSecurityKey" => Some(serde_json::from_value::<clear_user_security_key::Body>(value.clone()).map(|_| ())),
        "clearUserAuthenticatorApp" => Some(serde_json::from_value::<clear_user_authenticator_app::Body>(value.clone()).map(|_| ())),
        "createUser" => Some(serde_json::from_value::<create_user::Body>(value.clone()).map(|_| ())),
        "createUserAppPassword" => Some(serde_json::from_value::<create_user_app_password::Body>(value.clone()).map(|_| ())),
        "deactivateUserPublishedDid" => Some(serde_json::from_value::<deactivate_user_published_did::Body>(value.clone()).map(|_| ())),
        "disableUserAccount" => Some(serde_json::from_value::<disable_user_account::Body>(value.clone()).map(|_| ())),
        "disableUserSecondFactors" => Some(serde_json::from_value::<disable_user_second_factors::Body>(value.clone()).map(|_| ())),
        "disableUserPasskeys" => Some(serde_json::from_value::<disable_user_passkeys::Body>(value.clone()).map(|_| ())),
        "enableUserAccount" => Some(serde_json::from_value::<enable_user_account::Body>(value.clone()).map(|_| ())),
        "enrolUserSelfIssuedSubject" => Some(serde_json::from_value::<enrol_user_self_issued_subject::Body>(value.clone()).map(|_| ())),
        "exportUserLdif" => Some(serde_json::from_value::<export_user_ldif::Body>(value.clone()).map(|_| ())),
        "linkUserFederation" => Some(serde_json::from_value::<link_user_federation::Body>(value.clone()).map(|_| ())),
        "unlinkUserFederation" => Some(serde_json::from_value::<unlink_user_federation::Body>(value.clone()).map(|_| ())),
        "finishUserPasskeyEnrolment" => Some(serde_json::from_value::<finish_user_passkey_enrolment::Body>(value.clone()).map(|_| ())),
        "finishUserPasskeyUpgrade" => Some(serde_json::from_value::<finish_user_passkey_upgrade::Body>(value.clone()).map(|_| ())),
        "importUserLdif" => Some(serde_json::from_value::<import_user_ldif::Body>(value.clone()).map(|_| ())),
        "issueActivationLink" => Some(serde_json::from_value::<issue_activation_link::Body>(value.clone()).map(|_| ())),
        "issuePasswordResetLink" => Some(serde_json::from_value::<issue_password_reset_link::Body>(value.clone()).map(|_| ())),
        "issueUserSigningCertificate" => Some(serde_json::from_value::<issue_user_signing_certificate::Body>(value.clone()).map(|_| ())),
        "proveUserPasskeyUpgrade" => Some(serde_json::from_value::<prove_user_passkey_upgrade::Body>(value.clone()).map(|_| ())),
        "recordUserVerification" => Some(serde_json::from_value::<record_user_verification::Body>(value.clone()).map(|_| ())),
        "removeUserAttributeValue" => Some(serde_json::from_value::<remove_user_attribute_value::Body>(value.clone()).map(|_| ())),
        "removeUserCertificate" => Some(serde_json::from_value::<remove_user_certificate::Body>(value.clone()).map(|_| ())),
        "removeUserDevice" => Some(serde_json::from_value::<remove_user_device::Body>(value.clone()).map(|_| ())),
        "removeUserSelfIssuedSubject" => Some(serde_json::from_value::<remove_user_self_issued_subject::Body>(value.clone()).map(|_| ())),
        "removeServiceAccountOwner" => Some(serde_json::from_value::<remove_service_account_owner::Body>(value.clone()).map(|_| ())),
        "removeUserVerification" => Some(serde_json::from_value::<remove_user_verification::Body>(value.clone()).map(|_| ())),
        "renameUserPasskey" => Some(serde_json::from_value::<rename_user_passkey::Body>(value.clone()).map(|_| ())),
        "requireUserSecondFactor" => Some(serde_json::from_value::<require_user_second_factor::Body>(value.clone()).map(|_| ())),
        "resetUserPassword" => Some(serde_json::from_value::<reset_user_password::Body>(value.clone()).map(|_| ())),
        "revokeUserAppPassword" => Some(serde_json::from_value::<revoke_user_app_password::Body>(value.clone()).map(|_| ())),
        "revokeUserSigningCertificate" => Some(serde_json::from_value::<revoke_user_signing_certificate::Body>(value.clone()).map(|_| ())),
        "rotateServiceAccountPassword" => Some(serde_json::from_value::<rotate_service_account_password::Body>(value.clone()).map(|_| ())),
        "setUserAttribute" => Some(serde_json::from_value::<set_user_attribute::Body>(value.clone()).map(|_| ())),
        "setUserAudSub" => Some(serde_json::from_value::<set_user_aud_sub::Body>(value.clone()).map(|_| ())),
        "setUserDelegationSemantics" => Some(serde_json::from_value::<set_user_delegation_semantics::Body>(value.clone()).map(|_| ())),
        "setUserMail" => Some(serde_json::from_value::<set_user_mail::Body>(value.clone()).map(|_| ())),
        "setUserMayAct" => Some(serde_json::from_value::<set_user_may_act::Body>(value.clone()).map(|_| ())),
        "setUserNotDelegated" => Some(serde_json::from_value::<set_user_not_delegated::Body>(value.clone()).map(|_| ())),
        "setUserPassword" => Some(serde_json::from_value::<set_user_password::Body>(value.clone()).map(|_| ())),
        "setUserPreferredSelfIssuedSubject" => Some(serde_json::from_value::<set_user_preferred_self_issued_subject::Body>(value.clone()).map(|_| ())),
        "setUserPseudonyms" => Some(serde_json::from_value::<set_user_pseudonyms::Body>(value.clone()).map(|_| ())),
        "setUserServiceAccount" => Some(serde_json::from_value::<set_user_service_account::Body>(value.clone()).map(|_| ())),
        "setServiceAccountDestination" => Some(serde_json::from_value::<set_service_account_destination::Body>(value.clone()).map(|_| ())),
        "stopRequiringUserSecondFactor" => Some(serde_json::from_value::<stop_requiring_user_second_factor::Body>(value.clone()).map(|_| ())),
        "updateUserFields" => Some(serde_json::from_value::<update_user_fields::Body>(value.clone()).map(|_| ())),
        "startVerification" => Some(serde_json::from_value::<start_verification::Body>(value.clone()).map(|_| ())),
        "addRequestedClaim" => Some(serde_json::from_value::<add_requested_claim::Body>(value.clone()).map(|_| ())),
        "resetRequestedClaims" => Some(serde_json::from_value::<reset_requested_claims::Body>(value.clone()).map(|_| ())),
        "setRequestFormat" => Some(serde_json::from_value::<set_request_format::Body>(value.clone()).map(|_| ())),
        "removeRequestedClaim" => Some(serde_json::from_value::<remove_requested_claim::Body>(value.clone()).map(|_| ())),
        "selectRequestedClaims" => Some(serde_json::from_value::<select_requested_claims::Body>(value.clone()).map(|_| ())),
        "addXacmlAlternative" => Some(serde_json::from_value::<add_xacml_alternative::Body>(value.clone()).map(|_| ())),
        "addXacmlArgument" => Some(serde_json::from_value::<add_xacml_argument::Body>(value.clone()).map(|_| ())),
        "addXacmlAssignment" => Some(serde_json::from_value::<add_xacml_assignment::Body>(value.clone()).map(|_| ())),
        "addXacmlCondition" => Some(serde_json::from_value::<add_xacml_condition::Body>(value.clone()).map(|_| ())),
        "addXacmlMatch" => Some(serde_json::from_value::<add_xacml_match::Body>(value.clone()).map(|_| ())),
        "addXacmlPolicyToSet" => Some(serde_json::from_value::<add_xacml_policy_to_set::Body>(value.clone()).map(|_| ())),
        "addXacmlPolicyAdvice" => Some(serde_json::from_value::<add_xacml_policy_advice::Body>(value.clone()).map(|_| ())),
        "addXacmlPolicyObligation" => Some(serde_json::from_value::<add_xacml_policy_obligation::Body>(value.clone()).map(|_| ())),
        "addXacmlPolicyReference" => Some(serde_json::from_value::<add_xacml_policy_reference::Body>(value.clone()).map(|_| ())),
        "addXacmlPolicySetToSet" => Some(serde_json::from_value::<add_xacml_policy_set_to_set::Body>(value.clone()).map(|_| ())),
        "addXacmlPolicySetReference" => Some(serde_json::from_value::<add_xacml_policy_set_reference::Body>(value.clone()).map(|_| ())),
        "addXacmlRule" => Some(serde_json::from_value::<add_xacml_rule::Body>(value.clone()).map(|_| ())),
        "addXacmlRuleAdvice" => Some(serde_json::from_value::<add_xacml_rule_advice::Body>(value.clone()).map(|_| ())),
        "addXacmlRuleObligation" => Some(serde_json::from_value::<add_xacml_rule_obligation::Body>(value.clone()).map(|_| ())),
        "addXacmlTargetClause" => Some(serde_json::from_value::<add_xacml_target_clause::Body>(value.clone()).map(|_| ())),
        "addXacmlVariable" => Some(serde_json::from_value::<add_xacml_variable::Body>(value.clone()).map(|_| ())),
        "approveAuthzenAccessRequest" => Some(serde_json::from_value::<approve_authzen_access_request::Body>(value.clone()).map(|_| ())),
        "cancelAuthzenAccessRequest" => Some(serde_json::from_value::<cancel_authzen_access_request::Body>(value.clone()).map(|_| ())),
        "denyAuthzenAccessRequest" => Some(serde_json::from_value::<deny_authzen_access_request::Body>(value.clone()).map(|_| ())),
        "removeAuthzenAttribute" => Some(serde_json::from_value::<remove_authzen_attribute::Body>(value.clone()).map(|_| ())),
        "revokeAuthzenAccessRequest" => Some(serde_json::from_value::<revoke_authzen_access_request::Body>(value.clone()).map(|_| ())),
        "setAuthzenAttribute" => Some(serde_json::from_value::<set_authzen_attribute::Body>(value.clone()).map(|_| ())),
        "setAuthzenCallbacks" => Some(serde_json::from_value::<set_authzen_callbacks::Body>(value.clone()).map(|_| ())),
        "setAuthzenScope" => Some(serde_json::from_value::<set_authzen_scope::Body>(value.clone()).map(|_| ())),
        "createXacmlPolicy" => Some(serde_json::from_value::<create_xacml_policy::Body>(value.clone()).map(|_| ())),
        "deleteXacmlPolicy" => Some(serde_json::from_value::<delete_xacml_policy::Body>(value.clone()).map(|_| ())),
        "disableXacmlPolicy" => Some(serde_json::from_value::<disable_xacml_policy::Body>(value.clone()).map(|_| ())),
        "disableXacmlPep" => Some(serde_json::from_value::<disable_xacml_pep::Body>(value.clone()).map(|_| ())),
        "editXacmlApply" => Some(serde_json::from_value::<edit_xacml_apply::Body>(value.clone()).map(|_| ())),
        "editXacmlAssignment" => Some(serde_json::from_value::<edit_xacml_assignment::Body>(value.clone()).map(|_| ())),
        "editXacmlDesignator" => Some(serde_json::from_value::<edit_xacml_designator::Body>(value.clone()).map(|_| ())),
        "editXacmlFunctionReference" => Some(serde_json::from_value::<edit_xacml_function_reference::Body>(value.clone()).map(|_| ())),
        "editXacmlMatch" => Some(serde_json::from_value::<edit_xacml_match::Body>(value.clone()).map(|_| ())),
        "editXacmlObligation" => Some(serde_json::from_value::<edit_xacml_obligation::Body>(value.clone()).map(|_| ())),
        "editXacmlPolicy" => Some(serde_json::from_value::<edit_xacml_policy::Body>(value.clone()).map(|_| ())),
        "editXacmlReference" => Some(serde_json::from_value::<edit_xacml_reference::Body>(value.clone()).map(|_| ())),
        "editXacmlRule" => Some(serde_json::from_value::<edit_xacml_rule::Body>(value.clone()).map(|_| ())),
        "editXacmlSelector" => Some(serde_json::from_value::<edit_xacml_selector::Body>(value.clone()).map(|_| ())),
        "editXacmlValue" => Some(serde_json::from_value::<edit_xacml_value::Body>(value.clone()).map(|_| ())),
        "renameXacmlVariable" => Some(serde_json::from_value::<rename_xacml_variable::Body>(value.clone()).map(|_| ())),
        "enableXacmlPolicy" => Some(serde_json::from_value::<enable_xacml_policy::Body>(value.clone()).map(|_| ())),
        "enableXacmlPep" => Some(serde_json::from_value::<enable_xacml_pep::Body>(value.clone()).map(|_| ())),
        "forgetXacmlPep" => Some(serde_json::from_value::<forget_xacml_pep::Body>(value.clone()).map(|_| ())),
        "importXacmlAlfa" => Some(serde_json::from_value::<import_xacml_alfa::Body>(value.clone()).map(|_| ())),
        "issueXacmlPepCertificate" => Some(serde_json::from_value::<issue_xacml_pep_certificate::Body>(value.clone()).map(|_| ())),
        "removeXacmlNode" => Some(serde_json::from_value::<remove_xacml_node::Body>(value.clone()).map(|_| ())),
        "setXacmlApply" => Some(serde_json::from_value::<set_xacml_apply::Body>(value.clone()).map(|_| ())),
        "setXacmlDesignator" => Some(serde_json::from_value::<set_xacml_designator::Body>(value.clone()).map(|_| ())),
        "setXacmlExpressionFunction" => Some(serde_json::from_value::<set_xacml_expression_function::Body>(value.clone()).map(|_| ())),
        "setXacmlExpressionSelector" => Some(serde_json::from_value::<set_xacml_expression_selector::Body>(value.clone()).map(|_| ())),
        "setXacmlValue" => Some(serde_json::from_value::<set_xacml_value::Body>(value.clone()).map(|_| ())),
        "setXacmlVariable" => Some(serde_json::from_value::<set_xacml_variable::Body>(value.clone()).map(|_| ())),
        "setXacmlRootPolicy" => Some(serde_json::from_value::<set_xacml_root_policy::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getServiceAccounts", 200) => Some(serde_json::from_value::<get_service_accounts::Answer200>(value.clone()).map(|_| ())),
        ("getUsers", 200) => Some(serde_json::from_value::<get_users::Answer200>(value.clone()).map(|_| ())),
        ("addUserAttributeValue", 200) => Some(serde_json::from_value::<add_user_attribute_value::Answer200>(value.clone()).map(|_| ())),
        ("addUserCertificate", 200) => Some(serde_json::from_value::<add_user_certificate::Answer200>(value.clone()).map(|_| ())),
        ("addServiceAccountOwner", 200) => Some(serde_json::from_value::<add_service_account_owner::Answer200>(value.clone()).map(|_| ())),
        ("answerUserCibaRequest", 200) => Some(serde_json::from_value::<answer_user_ciba_request::Answer200>(value.clone()).map(|_| ())),
        ("getUserAppPasswords", 200) => Some(serde_json::from_value::<get_user_app_passwords::Answer200>(value.clone()).map(|_| ())),
        ("beginUserPasskeyEnrolment", 200) => Some(serde_json::from_value::<begin_user_passkey_enrolment::Answer200>(value.clone()).map(|_| ())),
        ("beginUserPasskeyUpgrade", 200) => Some(serde_json::from_value::<begin_user_passkey_upgrade::Answer200>(value.clone()).map(|_| ())),
        ("cancelUserPasskeyUpgrade", 200) => Some(serde_json::from_value::<cancel_user_passkey_upgrade::Answer200>(value.clone()).map(|_| ())),
        ("getUserCertificates", 200) => Some(serde_json::from_value::<get_user_certificates::Answer200>(value.clone()).map(|_| ())),
        ("clearUserBackupCodes", 200) => Some(serde_json::from_value::<clear_user_backup_codes::Answer200>(value.clone()).map(|_| ())),
        ("clearUserEmailFactor", 200) => Some(serde_json::from_value::<clear_user_email_factor::Answer200>(value.clone()).map(|_| ())),
        ("clearUserSecurityKey", 200) => Some(serde_json::from_value::<clear_user_security_key::Answer200>(value.clone()).map(|_| ())),
        ("clearUserAuthenticatorApp", 200) => Some(serde_json::from_value::<clear_user_authenticator_app::Answer200>(value.clone()).map(|_| ())),
        ("createUser", 200) => Some(serde_json::from_value::<create_user::Answer200>(value.clone()).map(|_| ())),
        ("createUserAppPassword", 200) => Some(serde_json::from_value::<create_user_app_password::Answer200>(value.clone()).map(|_| ())),
        ("deactivateUserPublishedDid", 200) => Some(serde_json::from_value::<deactivate_user_published_did::Answer200>(value.clone()).map(|_| ())),
        ("getUserDevices", 200) => Some(serde_json::from_value::<get_user_devices::Answer200>(value.clone()).map(|_| ())),
        ("disableUserAccount", 200) => Some(serde_json::from_value::<disable_user_account::Answer200>(value.clone()).map(|_| ())),
        ("disableUserSecondFactors", 200) => Some(serde_json::from_value::<disable_user_second_factors::Answer200>(value.clone()).map(|_| ())),
        ("disableUserPasskeys", 200) => Some(serde_json::from_value::<disable_user_passkeys::Answer200>(value.clone()).map(|_| ())),
        ("enableUserAccount", 200) => Some(serde_json::from_value::<enable_user_account::Answer200>(value.clone()).map(|_| ())),
        ("enrolUserSelfIssuedSubject", 200) => Some(serde_json::from_value::<enrol_user_self_issued_subject::Answer200>(value.clone()).map(|_| ())),
        ("exportUserLdif", 200) => Some(serde_json::from_value::<export_user_ldif::Answer200>(value.clone()).map(|_| ())),
        ("linkUserFederation", 200) => Some(serde_json::from_value::<link_user_federation::Answer200>(value.clone()).map(|_| ())),
        ("unlinkUserFederation", 200) => Some(serde_json::from_value::<unlink_user_federation::Answer200>(value.clone()).map(|_| ())),
        ("finishUserPasskeyEnrolment", 200) => Some(serde_json::from_value::<finish_user_passkey_enrolment::Answer200>(value.clone()).map(|_| ())),
        ("finishUserPasskeyUpgrade", 200) => Some(serde_json::from_value::<finish_user_passkey_upgrade::Answer200>(value.clone()).map(|_| ())),
        ("importUserLdif", 200) => Some(serde_json::from_value::<import_user_ldif::Answer200>(value.clone()).map(|_| ())),
        ("issueActivationLink", 200) => Some(serde_json::from_value::<issue_activation_link::Answer200>(value.clone()).map(|_| ())),
        ("issuePasswordResetLink", 200) => Some(serde_json::from_value::<issue_password_reset_link::Answer200>(value.clone()).map(|_| ())),
        ("issueUserSigningCertificate", 200) => Some(serde_json::from_value::<issue_user_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getNewUserForm", 200) => Some(serde_json::from_value::<get_new_user_form::Answer200>(value.clone()).map(|_| ())),
        ("proveUserPasskeyUpgrade", 200) => Some(serde_json::from_value::<prove_user_passkey_upgrade::Answer200>(value.clone()).map(|_| ())),
        ("getUserPublishedDids", 200) => Some(serde_json::from_value::<get_user_published_dids::Answer200>(value.clone()).map(|_| ())),
        ("recordUserVerification", 200) => Some(serde_json::from_value::<record_user_verification::Answer200>(value.clone()).map(|_| ())),
        ("removeUserAttributeValue", 200) => Some(serde_json::from_value::<remove_user_attribute_value::Answer200>(value.clone()).map(|_| ())),
        ("removeUserCertificate", 200) => Some(serde_json::from_value::<remove_user_certificate::Answer200>(value.clone()).map(|_| ())),
        ("removeUserDevice", 200) => Some(serde_json::from_value::<remove_user_device::Answer200>(value.clone()).map(|_| ())),
        ("removeUserSelfIssuedSubject", 200) => Some(serde_json::from_value::<remove_user_self_issued_subject::Answer200>(value.clone()).map(|_| ())),
        ("removeServiceAccountOwner", 200) => Some(serde_json::from_value::<remove_service_account_owner::Answer200>(value.clone()).map(|_| ())),
        ("removeUserVerification", 200) => Some(serde_json::from_value::<remove_user_verification::Answer200>(value.clone()).map(|_| ())),
        ("renameUserPasskey", 200) => Some(serde_json::from_value::<rename_user_passkey::Answer200>(value.clone()).map(|_| ())),
        ("requireUserSecondFactor", 200) => Some(serde_json::from_value::<require_user_second_factor::Answer200>(value.clone()).map(|_| ())),
        ("resetUserPassword", 200) => Some(serde_json::from_value::<reset_user_password::Answer200>(value.clone()).map(|_| ())),
        ("revokeUserAppPassword", 200) => Some(serde_json::from_value::<revoke_user_app_password::Answer200>(value.clone()).map(|_| ())),
        ("revokeUserSigningCertificate", 200) => Some(serde_json::from_value::<revoke_user_signing_certificate::Answer200>(value.clone()).map(|_| ())),
        ("rotateServiceAccountPassword", 200) => Some(serde_json::from_value::<rotate_service_account_password::Answer200>(value.clone()).map(|_| ())),
        ("getUserSelfIssuedSubjects", 200) => Some(serde_json::from_value::<get_user_self_issued_subjects::Answer200>(value.clone()).map(|_| ())),
        ("setUserAttribute", 200) => Some(serde_json::from_value::<set_user_attribute::Answer200>(value.clone()).map(|_| ())),
        ("setUserAudSub", 200) => Some(serde_json::from_value::<set_user_aud_sub::Answer200>(value.clone()).map(|_| ())),
        ("setUserDelegationSemantics", 200) => Some(serde_json::from_value::<set_user_delegation_semantics::Answer200>(value.clone()).map(|_| ())),
        ("setUserMail", 200) => Some(serde_json::from_value::<set_user_mail::Answer200>(value.clone()).map(|_| ())),
        ("setUserMayAct", 200) => Some(serde_json::from_value::<set_user_may_act::Answer200>(value.clone()).map(|_| ())),
        ("setUserNotDelegated", 200) => Some(serde_json::from_value::<set_user_not_delegated::Answer200>(value.clone()).map(|_| ())),
        ("setUserPassword", 200) => Some(serde_json::from_value::<set_user_password::Answer200>(value.clone()).map(|_| ())),
        ("setUserPreferredSelfIssuedSubject", 200) => Some(serde_json::from_value::<set_user_preferred_self_issued_subject::Answer200>(value.clone()).map(|_| ())),
        ("setUserPseudonyms", 200) => Some(serde_json::from_value::<set_user_pseudonyms::Answer200>(value.clone()).map(|_| ())),
        ("setUserServiceAccount", 200) => Some(serde_json::from_value::<set_user_service_account::Answer200>(value.clone()).map(|_| ())),
        ("setServiceAccountDestination", 200) => Some(serde_json::from_value::<set_service_account_destination::Answer200>(value.clone()).map(|_| ())),
        ("stopRequiringUserSecondFactor", 200) => Some(serde_json::from_value::<stop_requiring_user_second_factor::Answer200>(value.clone()).map(|_| ())),
        ("updateUserFields", 200) => Some(serde_json::from_value::<update_user_fields::Answer200>(value.clone()).map(|_| ())),
        ("getUserVerifications", 200) => Some(serde_json::from_value::<get_user_verifications::Answer200>(value.clone()).map(|_| ())),
        ("getVerifications", 200) => Some(serde_json::from_value::<get_verifications::Answer200>(value.clone()).map(|_| ())),
        ("startVerification", 200) => Some(serde_json::from_value::<start_verification::Answer200>(value.clone()).map(|_| ())),
        ("getVerifierRequest", 200) => Some(serde_json::from_value::<get_verifier_request::Answer200>(value.clone()).map(|_| ())),
        ("addRequestedClaim", 200) => Some(serde_json::from_value::<add_requested_claim::Answer200>(value.clone()).map(|_| ())),
        ("resetRequestedClaims", 200) => Some(serde_json::from_value::<reset_requested_claims::Answer200>(value.clone()).map(|_| ())),
        ("setRequestFormat", 200) => Some(serde_json::from_value::<set_request_format::Answer200>(value.clone()).map(|_| ())),
        ("removeRequestedClaim", 200) => Some(serde_json::from_value::<remove_requested_claim::Answer200>(value.clone()).map(|_| ())),
        ("selectRequestedClaims", 200) => Some(serde_json::from_value::<select_requested_claims::Answer200>(value.clone()).map(|_| ())),
        ("getWebauthnSettings", 200) => Some(serde_json::from_value::<get_webauthn_settings::Answer200>(value.clone()).map(|_| ())),
        ("getWsFedSettings", 200) => Some(serde_json::from_value::<get_ws_fed_settings::Answer200>(value.clone()).map(|_| ())),
        ("getWsTrustSettings", 200) => Some(serde_json::from_value::<get_ws_trust_settings::Answer200>(value.clone()).map(|_| ())),
        ("getXacml", 200) => Some(serde_json::from_value::<get_xacml::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlAlternative", 200) => Some(serde_json::from_value::<add_xacml_alternative::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlArgument", 200) => Some(serde_json::from_value::<add_xacml_argument::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlAssignment", 200) => Some(serde_json::from_value::<add_xacml_assignment::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlCondition", 200) => Some(serde_json::from_value::<add_xacml_condition::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlMatch", 200) => Some(serde_json::from_value::<add_xacml_match::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlPolicyToSet", 200) => Some(serde_json::from_value::<add_xacml_policy_to_set::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlPolicyAdvice", 200) => Some(serde_json::from_value::<add_xacml_policy_advice::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlPolicyObligation", 200) => Some(serde_json::from_value::<add_xacml_policy_obligation::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlPolicyReference", 200) => Some(serde_json::from_value::<add_xacml_policy_reference::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlPolicySetToSet", 200) => Some(serde_json::from_value::<add_xacml_policy_set_to_set::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlPolicySetReference", 200) => Some(serde_json::from_value::<add_xacml_policy_set_reference::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlRule", 200) => Some(serde_json::from_value::<add_xacml_rule::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlRuleAdvice", 200) => Some(serde_json::from_value::<add_xacml_rule_advice::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlRuleObligation", 200) => Some(serde_json::from_value::<add_xacml_rule_obligation::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlTargetClause", 200) => Some(serde_json::from_value::<add_xacml_target_clause::Answer200>(value.clone()).map(|_| ())),
        ("addXacmlVariable", 200) => Some(serde_json::from_value::<add_xacml_variable::Answer200>(value.clone()).map(|_| ())),
        ("getXacmlAuthzen", 200) => Some(serde_json::from_value::<get_xacml_authzen::Answer200>(value.clone()).map(|_| ())),
        ("approveAuthzenAccessRequest", 200) => Some(serde_json::from_value::<approve_authzen_access_request::Answer200>(value.clone()).map(|_| ())),
        ("cancelAuthzenAccessRequest", 200) => Some(serde_json::from_value::<cancel_authzen_access_request::Answer200>(value.clone()).map(|_| ())),
        ("denyAuthzenAccessRequest", 200) => Some(serde_json::from_value::<deny_authzen_access_request::Answer200>(value.clone()).map(|_| ())),
        ("removeAuthzenAttribute", 200) => Some(serde_json::from_value::<remove_authzen_attribute::Answer200>(value.clone()).map(|_| ())),
        ("revokeAuthzenAccessRequest", 200) => Some(serde_json::from_value::<revoke_authzen_access_request::Answer200>(value.clone()).map(|_| ())),
        ("setAuthzenAttribute", 200) => Some(serde_json::from_value::<set_authzen_attribute::Answer200>(value.clone()).map(|_| ())),
        ("setAuthzenCallbacks", 200) => Some(serde_json::from_value::<set_authzen_callbacks::Answer200>(value.clone()).map(|_| ())),
        ("setAuthzenScope", 200) => Some(serde_json::from_value::<set_authzen_scope::Answer200>(value.clone()).map(|_| ())),
        ("createXacmlPolicy", 200) => Some(serde_json::from_value::<create_xacml_policy::Answer200>(value.clone()).map(|_| ())),
        ("getXacmlDecision", 200) => Some(serde_json::from_value::<get_xacml_decision::Answer200>(value.clone()).map(|_| ())),
        ("deleteXacmlPolicy", 200) => Some(serde_json::from_value::<delete_xacml_policy::Answer200>(value.clone()).map(|_| ())),
        ("disableXacmlPolicy", 200) => Some(serde_json::from_value::<disable_xacml_policy::Answer200>(value.clone()).map(|_| ())),
        ("disableXacmlPep", 200) => Some(serde_json::from_value::<disable_xacml_pep::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlApply", 200) => Some(serde_json::from_value::<edit_xacml_apply::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlAssignment", 200) => Some(serde_json::from_value::<edit_xacml_assignment::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlDesignator", 200) => Some(serde_json::from_value::<edit_xacml_designator::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlFunctionReference", 200) => Some(serde_json::from_value::<edit_xacml_function_reference::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlMatch", 200) => Some(serde_json::from_value::<edit_xacml_match::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlObligation", 200) => Some(serde_json::from_value::<edit_xacml_obligation::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlPolicy", 200) => Some(serde_json::from_value::<edit_xacml_policy::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlReference", 200) => Some(serde_json::from_value::<edit_xacml_reference::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlRule", 200) => Some(serde_json::from_value::<edit_xacml_rule::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlSelector", 200) => Some(serde_json::from_value::<edit_xacml_selector::Answer200>(value.clone()).map(|_| ())),
        ("editXacmlValue", 200) => Some(serde_json::from_value::<edit_xacml_value::Answer200>(value.clone()).map(|_| ())),
        ("renameXacmlVariable", 200) => Some(serde_json::from_value::<rename_xacml_variable::Answer200>(value.clone()).map(|_| ())),
        ("getXacmlEditor", 200) => Some(serde_json::from_value::<get_xacml_editor::Answer200>(value.clone()).map(|_| ())),
        ("enableXacmlPolicy", 200) => Some(serde_json::from_value::<enable_xacml_policy::Answer200>(value.clone()).map(|_| ())),
        ("enableXacmlPep", 200) => Some(serde_json::from_value::<enable_xacml_pep::Answer200>(value.clone()).map(|_| ())),
        ("forgetXacmlPep", 200) => Some(serde_json::from_value::<forget_xacml_pep::Answer200>(value.clone()).map(|_| ())),
        ("importXacmlAlfa", 200) => Some(serde_json::from_value::<import_xacml_alfa::Answer200>(value.clone()).map(|_| ())),
        ("issueXacmlPepCertificate", 200) => Some(serde_json::from_value::<issue_xacml_pep_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getXacmlMonitor", 200) => Some(serde_json::from_value::<get_xacml_monitor::Answer200>(value.clone()).map(|_| ())),
        ("getXacmlPeps", 200) => Some(serde_json::from_value::<get_xacml_peps::Answer200>(value.clone()).map(|_| ())),
        ("getXacmlPolicies", 200) => Some(serde_json::from_value::<get_xacml_policies::Answer200>(value.clone()).map(|_| ())),
        ("removeXacmlNode", 200) => Some(serde_json::from_value::<remove_xacml_node::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlApply", 200) => Some(serde_json::from_value::<set_xacml_apply::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlDesignator", 200) => Some(serde_json::from_value::<set_xacml_designator::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlExpressionFunction", 200) => Some(serde_json::from_value::<set_xacml_expression_function::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlExpressionSelector", 200) => Some(serde_json::from_value::<set_xacml_expression_selector::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlValue", 200) => Some(serde_json::from_value::<set_xacml_value::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlVariable", 200) => Some(serde_json::from_value::<set_xacml_variable::Answer200>(value.clone()).map(|_| ())),
        ("setXacmlRootPolicy", 200) => Some(serde_json::from_value::<set_xacml_root_policy::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
