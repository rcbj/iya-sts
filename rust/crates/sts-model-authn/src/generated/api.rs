// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

pub mod components {
    pub type SignInId = String;

}

/// Lists every operation of this API
pub mod get_index {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api";
    pub const OPERATION_ID: &str = "getIndex";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200OperationsItemMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OperationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200OperationsItemMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(rename = "operationId", default, skip_serializing_if = "Option::is_none")]
        pub operation_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub access: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub mirrors: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub action: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub api: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub openapi: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<Answer200OperationsItem>>,
    }
}

/// The accounts this browser holds
pub mod get_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/accounts";
    pub const OPERATION_ID: &str = "getAccounts";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200AccountsItemState {
        #[serde(rename = "signed-in")]
        SignedIn,
        #[serde(rename = "signed-out")]
        SignedOut,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200AccountsItemState>,
        #[serde(rename = "signedInAt", default, skip_serializing_if = "Option::is_none")]
        pub signed_in_at: Option<f64>,
        #[serde(rename = "authTime", default, skip_serializing_if = "Option::is_none")]
        pub auth_time: Option<f64>,
        #[serde(rename = "signedOutAt", default, skip_serializing_if = "Option::is_none")]
        pub signed_out_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200AccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(rename = "anotherAccount", default, skip_serializing_if = "Option::is_none")]
        pub another_account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
    }
}

/// What the OAuth consent screen asks
pub mod get_consent {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/consent/{id}";
    pub const OPERATION_ID: &str = "getConsent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewClientDisplay {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub logo: Option<String>,
        #[serde(rename = "logoOrigin", default, skip_serializing_if = "Option::is_none")]
        pub logo_origin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tos: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewScopesItemPermission {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
        pub base_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewScopesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permission: Option<Answer200ViewScopesItemPermission>,
        #[serde(rename = "releasesDid", default, skip_serializing_if = "Option::is_none")]
        pub releases_did: Option<bool>,
        #[serde(rename = "signsIn", default, skip_serializing_if = "Option::is_none")]
        pub signs_in: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAuthorizationDetailsItemMembersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAuthorizationDetailsItem {
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<Answer200ViewAuthorizationDetailsItemMembersItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAlreadyItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub global: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewLimitsItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub member: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewLimitsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub r: Option<i64>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        /// The limits member of an RFC 9396 authorization detail, as the client
        /// sent it: beyond the six members common/access_limits.ts names, every
        /// member is the API's own, under a schema an operator declared for its
        /// type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200ViewLimitsItemRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDetailsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consent: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<Answer200ViewClient>,
        #[serde(rename = "clientDisplay", default, skip_serializing_if = "Option::is_none")]
        pub client_display: Option<Answer200ViewClientDisplay>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<Vec<String>>,
        #[serde(rename = "lifetimeHours", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_hours: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<Answer200ViewScopesItem>>,
        #[serde(rename = "authorizationDetails", default, skip_serializing_if = "Option::is_none")]
        pub authorization_details: Option<Vec<Answer200ViewAuthorizationDetailsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub already: Option<Vec<Answer200ViewAlreadyItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<Vec<Answer200ViewLimitsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<Vec<Answer200ViewDetailsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Allows or denies what the consent screen asks
pub mod answer_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/consent/{id}";
    pub const OPERATION_ID: &str = "answerConsent";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "allow")]
        Allow,
        #[serde(rename = "deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub action: BodyAction,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Everything a sign-out would end
pub mod get_sign_out {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/logout";
    pub const OPERATION_ID: &str = "getSignOut";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewState {
        #[serde(rename = "inventory")]
        Inventory,
        #[serde(rename = "accounts")]
        Accounts,
        #[serde(rename = "refused")]
        Refused,
        #[serde(rename = "nobody")]
        Nobody,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewNaming {
        #[serde(rename = "open")]
        Open,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "product")]
        Product,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFamiliesItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub detail: Option<Option<String>>,
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub started_at: Option<Option<f64>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
        #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub session_id: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFamiliesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200ViewFamiliesItemRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<f64>,
        #[serde(rename = "notListed", default, skip_serializing_if = "Option::is_none")]
        pub not_listed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failure: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub naming: Option<Answer200ViewNaming>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessions: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub families: Option<Vec<Answer200ViewFamiliesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listed: Option<f64>,
        #[serde(rename = "notListed", default, skip_serializing_if = "Option::is_none")]
        pub not_listed: Option<f64>,
        #[serde(rename = "maxRows", default, skip_serializing_if = "Option::is_none")]
        pub max_rows: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200ViewAccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preselected: Option<String>,
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }
}

/// Signs out: everything, or what was ticked
pub mod sign_out {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/logout";
    pub const OPERATION_ID: &str = "signOut";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyScopeV1 {
        #[serde(rename = "global")]
        Global,
        #[serde(rename = "selected")]
        Selected,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyScope {
        V1(BodyScopeV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<BodyScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub select: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "signed-out")]
        SignedOut,
        #[serde(rename = "inventory")]
        Inventory,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Scope {
        #[serde(rename = "global")]
        Global,
        #[serde(rename = "selected")]
        Selected,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormFields {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub result: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Answer200FormFields>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewState {
        #[serde(rename = "result")]
        Result,
        #[serde(rename = "refused")]
        Refused,
        #[serde(rename = "nobody")]
        Nobody,
        #[serde(rename = "accounts")]
        Accounts,
        #[serde(rename = "reauthenticate")]
        Reauthenticate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewScope {
        #[serde(rename = "global")]
        Global,
        #[serde(rename = "selected")]
        Selected,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTerminatedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSkippedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewNaming {
        #[serde(rename = "open")]
        Open,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "product")]
        Product,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewState>,
        /// With `state` reauthenticate: where to sign in again before ending
        /// another session, a path on this service that comes back to the sign-out
        /// page.
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<Answer200ViewScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminated: Option<Vec<Answer200ViewTerminatedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skipped: Option<Vec<Answer200ViewSkippedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<f64>,
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200ViewAccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preselected: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub naming: Option<Answer200ViewNaming>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(rename = "ownSessionEnded", default, skip_serializing_if = "Option::is_none")]
        pub own_session_ended: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<Answer200Scope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Which account a sign-out is for
pub mod get_sign_out_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/logout/accounts";
    pub const OPERATION_ID: &str = "getSignOutAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewNaming {
        #[serde(rename = "open")]
        Open,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "product")]
        Product,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200ViewAccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preselected: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub naming: Option<Answer200ViewNaming>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }
}

/// Chooses the account to sign out, or every account
pub mod choose_sign_out_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/logout/accounts";
    pub const OPERATION_ID: &str = "chooseSignOutAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub account: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "signed-out")]
        SignedOut,
        #[serde(rename = "inventory")]
        Inventory,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Scope {
        #[serde(rename = "global")]
        Global,
        #[serde(rename = "selected")]
        Selected,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormFields {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub result: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Answer200FormFields>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewState {
        #[serde(rename = "result")]
        Result,
        #[serde(rename = "refused")]
        Refused,
        #[serde(rename = "nobody")]
        Nobody,
        #[serde(rename = "accounts")]
        Accounts,
        #[serde(rename = "reauthenticate")]
        Reauthenticate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewScope {
        #[serde(rename = "global")]
        Global,
        #[serde(rename = "selected")]
        Selected,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTerminatedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSkippedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewNaming {
        #[serde(rename = "open")]
        Open,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "product")]
        Product,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewState>,
        /// With `state` reauthenticate: where to sign in again before ending
        /// another session, a path on this service that comes back to the sign-out
        /// page.
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<Answer200ViewScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminated: Option<Vec<Answer200ViewTerminatedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skipped: Option<Vec<Answer200ViewSkippedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<f64>,
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200ViewAccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preselected: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub naming: Option<Answer200ViewNaming>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(rename = "ownSessionEnded", default, skip_serializing_if = "Option::is_none")]
        pub own_session_ended: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<Answer200Scope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// What a second-factor or emailed-factor step's page shows
pub mod get_step {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/mfa/{id}";
    pub const OPERATION_ID: &str = "getStep";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryPageV1 {
        #[serde(rename = "totp")]
        Totp,
        #[serde(rename = "webauthn")]
        Webauthn,
        #[serde(rename = "backup-code")]
        BackupCode,
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "setup")]
        Setup,
        #[serde(rename = "email-code")]
        EmailCode,
        #[serde(rename = "email-link")]
        EmailLink,
        #[serde(rename = "email-link-open")]
        EmailLinkOpen,
        #[serde(rename = "post-login")]
        PostLogin,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum QueryPage {
        V1(QueryPageV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<QueryPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewLinks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub webauthn: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub backup: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewClientDisplay {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub logo: Option<String>,
        #[serde(rename = "logoOrigin", default, skip_serializing_if = "Option::is_none")]
        pub logo_origin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tos: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTotp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewBackupFactor {
        #[serde(rename = "passkey")]
        Passkey,
        #[serde(rename = "code")]
        Code,
        #[serde(rename = "link")]
        Link,
        #[serde(rename = "app")]
        App,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewBackup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<Answer200ViewBackupFactor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub back: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub low: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewWebauthnMode {
        #[serde(rename = "create")]
        Create,
        #[serde(rename = "get")]
        Get,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnChoicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnChosen {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnPostQuantumRefused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnHardwareRefused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnPostQuantumHelp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub register: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnFallback {
        #[serde(rename = "asksPostQuantum", default, skip_serializing_if = "Option::is_none")]
        pub asks_post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classical: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retrying: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub upgrade: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewWebauthnPostLoginUpgradePhase {
        #[serde(rename = "proof")]
        Proof,
        #[serde(rename = "registration")]
        Registration,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnPostLoginUpgrade {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub phase: Option<Answer200ViewWebauthnPostLoginUpgradePhase>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "previousAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub previous_algorithm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthnPostLogin {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub upgrade: Option<Answer200ViewWebauthnPostLoginUpgrade>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWebauthn {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<Answer200ViewWebauthnMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passwordless: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub choices: Option<Vec<Answer200ViewWebauthnChoicesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chosen: Option<Answer200ViewWebauthnChosen>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<String>,
        #[serde(rename = "postQuantumRefused", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_refused: Option<Answer200ViewWebauthnPostQuantumRefused>,
        #[serde(rename = "hardwareRefused", default, skip_serializing_if = "Option::is_none")]
        pub hardware_refused: Option<Answer200ViewWebauthnHardwareRefused>,
        #[serde(rename = "postQuantumHelp", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_help: Option<Answer200ViewWebauthnPostQuantumHelp>,
        #[serde(rename = "postQuantumAllowCredentials", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_allow_credentials: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback: Option<Answer200ViewWebauthnFallback>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub widened: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<String>>,
        #[serde(rename = "postLogin", default, skip_serializing_if = "Option::is_none")]
        pub post_login: Option<Answer200ViewWebauthnPostLogin>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lanes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
        pub user_verification: Option<String>,
        #[serde(rename = "residentKey", default, skip_serializing_if = "Option::is_none")]
        pub resident_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attachment: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewSetupState {
        #[serde(rename = "choose")]
        Choose,
        #[serde(rename = "totp")]
        Totp,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSetupOffered {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub webauthn: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSetupTotp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSetup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewSetupState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<Answer200ViewSetupOffered>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub optional: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proved: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recovery: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<Answer200ViewSetupTotp>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPostLogin {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub activity: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(rename = "canSkip", default, skip_serializing_if = "Option::is_none")]
        pub can_skip: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub separate: Option<bool>,
        #[serde(rename = "snoozeDays", default, skip_serializing_if = "Option::is_none")]
        pub snooze_days: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deadline: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewState {
        #[serde(rename = "ask")]
        Ask,
        #[serde(rename = "code")]
        Code,
        #[serde(rename = "wait")]
        Wait,
        #[serde(rename = "open")]
        Open,
        #[serde(rename = "elsewhere")]
        Elsewhere,
        #[serde(rename = "end")]
        End,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewKind {
        #[serde(rename = "code")]
        Code,
        #[serde(rename = "link")]
        Link,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOthers {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub webauthn: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub backup: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passwordless: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Answer200ViewLinks>,
        #[serde(rename = "clientDisplay", default, skip_serializing_if = "Option::is_none")]
        pub client_display: Option<Answer200ViewClientDisplay>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<Answer200ViewTotp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub amr: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub backup: Option<Answer200ViewBackup>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub webauthn: Option<Answer200ViewWebauthn>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setup: Option<Answer200ViewSetup>,
        #[serde(rename = "postLogin", default, skip_serializing_if = "Option::is_none")]
        pub post_login: Option<Answer200ViewPostLogin>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<Answer200ViewKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub primary: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub minutes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub others: Option<Answer200ViewOthers>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sentence: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }
}

/// Checks and spends a recovery code
pub mod spend_recovery_code {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/backup-code";
    pub const OPERATION_ID: &str = "spendRecoveryCode";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Spends a mailed sign-in link: its Continue button
pub mod spend_emailed_link {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/email-link/open";
    pub const OPERATION_ID: &str = "spendEmailedLink";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub t: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Checks an emailed code
pub mod check_emailed_code {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/email/code";
    pub const OPERATION_ID: &str = "checkEmailedCode";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Mails a code or a sign-in link for the step (#64)
pub mod send_emailed_factor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/email/send";
    pub const OPERATION_ID: &str = "sendEmailedFactor";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "code")]
        Code,
        #[serde(rename = "link")]
        Link,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub kind: BodyKind,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Checks a password as the second factor after a wallet
pub mod check_factor_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/password";
    pub const OPERATION_ID: &str = "checkFactorPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Chooses to register the passkey a post-login activity asks for
pub mod register_post_login_passkey {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/post-login/register";
    pub const OPERATION_ID: &str = "registerPostLoginPasskey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Puts a post-login activity off
pub mod skip_post_login_activity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/post-login/skip";
    pub const OPERATION_ID: &str = "skipPostLoginActivity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Confirms an authenticator app with its first code
pub mod confirm_app_enrolment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/setup/confirm";
    pub const OPERATION_ID: &str = "confirmAppEnrolment";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Begins enrolling an authenticator app at the set-up step
pub mod begin_app_enrolment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/setup/totp";
    pub const OPERATION_ID: &str = "beginAppEnrolment";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Chooses a passkey at the set-up step
pub mod begin_key_enrolment {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/setup/webauthn";
    pub const OPERATION_ID: &str = "beginKeyEnrolment";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Ignores an offered second factor (#246)
pub mod ignore_offer {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/skip";
    pub const OPERATION_ID: &str = "ignoreOffer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Leaves a sign-in step and starts the sign-in over
pub mod start_over {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/start-over";
    pub const OPERATION_ID: &str = "startOver";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Checks a one-time code from an authenticator app
pub mod check_code {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/totp";
    pub const OPERATION_ID: &str = "checkCode";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Verifies the passkey step's ceremony and finishes the step
pub mod finish_passkey_step {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/webauthn";
    pub const OPERATION_ID: &str = "finishPasskeyStep";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Arms the passkey step's ceremony
pub mod passkey_step_options {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/mfa/{id}/webauthn/options";
    pub const OPERATION_ID: &str = "passkeyStepOptions";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyLaneV1 {
        #[serde(rename = "classical")]
        Classical,
        #[serde(rename = "pqc")]
        Pqc,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyLane {
        V1(BodyLaneV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<BodyLane>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Mode {
        #[serde(rename = "create")]
        Create,
        #[serde(rename = "get")]
        Get,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200User {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OptionsRp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OptionsAuthenticatorSelection {
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
    pub struct Answer200Options {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rp: Option<Answer200OptionsRp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<Option<f64>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<f64>,
        #[serde(rename = "authenticatorSelection", default, skip_serializing_if = "Option::is_none")]
        pub authenticator_selection: Option<Answer200OptionsAuthenticatorSelection>,
        #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
        pub cred_props: Option<bool>,
        #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none")]
        pub min_pin_length: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hints: Option<Vec<String>>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
        pub user_verification: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Fallback {
        #[serde(rename = "asksPostQuantum", default, skip_serializing_if = "Option::is_none")]
        pub asks_post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classical: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retrying: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub upgrade: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<Answer200Mode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<Answer200User>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclude: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Answer200Options>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback: Option<Answer200Fallback>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<String>,
    }
}

/// This API's OpenAPI document
pub mod get_open_api {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/openapi.json";
    pub const OPERATION_ID: &str = "getOpenApi";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Info {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ServersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TagsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub openapi: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub info: Option<Answer200Info>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub servers: Option<Vec<Answer200ServersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<Answer200TagsItem>>,
        /// The operations and components of an OpenAPI document are that
        /// specification's vocabulary, not this API's, and this document describes
        /// itself with them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<serde_json::Value>,
        /// The operations and components of an OpenAPI document are that
        /// specification's vocabulary, not this API's, and this document describes
        /// itself with them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub components: Option<serde_json::Value>,
    }
}

/// The forced password change a sign-in is waiting on
pub mod get_password_change {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/password-change/{id}";
    pub const OPERATION_ID: &str = "getPasswordChange";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Stores the new password and continues the sign-in
pub mod change_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/password-change/{id}";
    pub const OPERATION_ID: &str = "changePassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub new_password: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm_password: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Leaves the forced password change and starts the sign-in over
pub mod start_over_from_password_change {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/password-change/{id}/start-over";
    pub const OPERATION_ID: &str = "startOverFromPasswordChange";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// What the sign-in screen offers for a pending sign-in
pub mod get_screen {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/pending/{id}";
    pub const OPERATION_ID: &str = "getScreen";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewKeys {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "mfaAllowed", default, skip_serializing_if = "Option::is_none")]
        pub mfa_allowed: Option<bool>,
        #[serde(rename = "primaryAllowed", default, skip_serializing_if = "Option::is_none")]
        pub primary_allowed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDemands {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passwordless: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEmail {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewClientDisplay {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub logo: Option<String>,
        #[serde(rename = "logoOrigin", default, skip_serializing_if = "Option::is_none")]
        pub logo_origin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tos: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewCertificate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "mfaNote", default, skip_serializing_if = "Option::is_none")]
        pub mfa_note: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPostQuantumRequired {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub register: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewPartnersKind {
        #[serde(rename = "own-one")]
        OwnOne,
        #[serde(rename = "own-many")]
        OwnMany,
        #[serde(rename = "any")]
        Any,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPartnersOptionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "protocolLabel", default, skip_serializing_if = "Option::is_none")]
        pub protocol_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPartners {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<Answer200ViewPartnersKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Vec<Answer200ViewPartnersOptionsItem>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewKerberosState {
        #[serde(rename = "offered")]
        Offered,
        #[serde(rename = "withheld-key")]
        WithheldKey,
        #[serde(rename = "withheld-mfa")]
        WithheldMfa,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewKerberos {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewKerberosState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewWalletState {
        #[serde(rename = "offered")]
        Offered,
        #[serde(rename = "withheld")]
        Withheld,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewWallet {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewWalletState>,
        #[serde(rename = "mfaNote", default, skip_serializing_if = "Option::is_none")]
        pub mfa_note: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub siop: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDetailsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locked: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub screen: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Answer200ViewKeys>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub demands: Option<Answer200ViewDemands>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub anonymous: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usernameless: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<Answer200ViewEmail>,
        #[serde(rename = "clientDisplay", default, skip_serializing_if = "Option::is_none")]
        pub client_display: Option<Answer200ViewClientDisplay>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reauthentication: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Answer200ViewCertificate>,
        #[serde(rename = "postQuantumRequired", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_required: Option<Answer200ViewPostQuantumRequired>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forgot: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub partners: Option<Answer200ViewPartners>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos: Option<Answer200ViewKerberos>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<Answer200ViewWallet>,
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fingerprint: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<Vec<Answer200ViewDetailsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The accounts a sign-in may continue as
pub mod get_account_choice {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/pending/{id}/accounts";
    pub const OPERATION_ID: &str = "getAccountChoice";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewAccountsItemState {
        #[serde(rename = "signed-in")]
        SignedIn,
        #[serde(rename = "signed-out")]
        SignedOut,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAccountsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<Answer200ViewAccountsItemState>,
        #[serde(rename = "signedInAt", default, skip_serializing_if = "Option::is_none")]
        pub signed_in_at: Option<f64>,
        #[serde(rename = "authTime", default, skip_serializing_if = "Option::is_none")]
        pub auth_time: Option<f64>,
        #[serde(rename = "signedOutAt", default, skip_serializing_if = "Option::is_none")]
        pub signed_out_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAnother {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub open: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDetailsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200ViewAccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub another: Option<Answer200ViewAnother>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<Vec<Answer200ViewDetailsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Signs in as another account
pub mod use_another_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/accounts/another";
    pub const OPERATION_ID: &str = "useAnotherAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Forgets a signed-out account
pub mod forget_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/accounts/forget";
    pub const OPERATION_ID: &str = "forgetAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub account: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Continues as one of this browser's accounts
pub mod select_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/accounts/select";
    pub const OPERATION_ID: &str = "selectAccount";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub account: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Continues without signing in
pub mod continue_anonymously {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/anonymous";
    pub const OPERATION_ID: &str = "continueAnonymously";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRememberBrowserV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRememberBrowser {
        V1(BodyRememberBrowserV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember_browser: Option<BodyRememberBrowser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_fp: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Declines the sign-in
pub mod cancel_sign_in {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/cancel";
    pub const OPERATION_ID: &str = "cancelSignIn";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Continues as the holder of the connection's TLS client certificate
pub mod continue_with_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/certificate";
    pub const OPERATION_ID: &str = "continueWithCertificate";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRememberBrowserV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRememberBrowser {
        V1(BodyRememberBrowserV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember_browser: Option<BodyRememberBrowser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_fp: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Mails a sign-in code or link as a first factor
pub mod sign_in_by_email {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/email";
    pub const OPERATION_ID: &str = "signInByEmail";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "code")]
        Code,
        #[serde(rename = "link")]
        Link,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRememberBrowserV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRememberBrowser {
        V1(BodyRememberBrowserV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        pub kind: BodyKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember_browser: Option<BodyRememberBrowser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_fp: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// The federation partners a sign-in may choose between
pub mod get_partners {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/pending/{id}/partners";
    pub const OPERATION_ID: &str = "getPartners";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPartnersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "protocolLabel", default, skip_serializing_if = "Option::is_none")]
        pub protocol_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDetailsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problems: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub partners: Option<Vec<Answer200ViewPartnersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<Vec<Answer200ViewDetailsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Signs in with a passkey and no username
pub mod sign_in_with_passkey {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/passkey";
    pub const OPERATION_ID: &str = "signInWithPasskey";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRememberBrowserV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRememberBrowser {
        V1(BodyRememberBrowserV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember_browser: Option<BodyRememberBrowser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_fp: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// Arms a passkey ceremony with no username
pub mod passkey_options {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/passkey/options";
    pub const OPERATION_ID: &str = "passkeyOptions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Options {
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
        pub user_verification: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hints: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Answer200Options>,
    }
}

/// Signs in with a username and password, or a passkey for the named account
pub mod sign_in_with_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/pending/{id}/password";
    pub const OPERATION_ID: &str = "signInWithPassword";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyUseWebauthnV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyUseWebauthn {
        V1(BodyUseWebauthnV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyWebauthnOnlyV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyWebauthnOnly {
        V1(BodyWebauthnOnlyV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRememberBrowserV1 {
        #[serde(rename = "0")]
        V0,
        #[serde(rename = "1")]
        V1,
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
        #[serde(rename = "yes")]
        Yes,
        #[serde(rename = "no")]
        No,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRememberBrowser {
        V1(BodyRememberBrowserV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub use_webauthn: Option<BodyUseWebauthn>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub webauthn_only: Option<BodyWebauthnOnly>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember_browser: Option<BodyRememberBrowser>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_fp: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    /// What the act leads to. `redirect`: go to `location` with a GET. `mfa`: the
    /// second-factor step `step`, whose page is `location`. `password-change`: the
    /// forced change, at `location`. `home-cell`: send `form` as it is. `stay`:
    /// draw the page again. `refused`: `errors` says why, in English; with
    /// `location` the sign-in screen says it, and with `end` the page ends.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
    }
}

/// What a wallet sign-in's start page needs
pub mod get_wallet_start {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/wallet";
    pub const OPERATION_ID: &str = "getWalletStart";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub siop: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub did_act: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewWallet {
        #[serde(rename = "start")]
        Start,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewChecksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewBackKind {
        #[serde(rename = "portal")]
        Portal,
        #[serde(rename = "screen")]
        Screen,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<Answer200ViewWallet>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
        pub second_factor: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub heading: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retry: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checks: Option<Vec<Answer200ViewChecksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub back: Option<String>,
        #[serde(rename = "backKind", default, skip_serializing_if = "Option::is_none")]
        pub back_kind: Option<Answer200ViewBackKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reissue: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }
}

/// Starts a wallet sign-in
pub mod start_wallet_sign_in {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/wallet";
    pub const OPERATION_ID: &str = "startWalletSignIn";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub siop: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub did_act: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "wait")]
        Wait,
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewChecksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewBackKind {
        #[serde(rename = "portal")]
        Portal,
        #[serde(rename = "screen")]
        Screen,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub heading: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retry: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checks: Option<Vec<Answer200ViewChecksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub back: Option<String>,
        #[serde(rename = "backKind", default, skip_serializing_if = "Option::is_none")]
        pub back_kind: Option<Answer200ViewBackKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reissue: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "expiresIn", default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// What the wallet sign-in's wait page draws
pub mod get_wallet_wait {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/authn-api/wallet/{state}";
    pub const OPERATION_ID: &str = "getWalletWait";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PreferredLanguage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub populated: Option<bool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewWallet {
        #[serde(rename = "wait")]
        Wait,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDcRequestData {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDcRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub data: Option<Answer200ViewDcRequestData>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewBackKind {
        #[serde(rename = "portal")]
        Portal,
        #[serde(rename = "screen")]
        Screen,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewChecksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<Answer200ViewWallet>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
        pub second_factor: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrol: Option<bool>,
        #[serde(rename = "dcRequest", default, skip_serializing_if = "Option::is_none")]
        pub dc_request: Option<Answer200ViewDcRequest>,
        #[serde(rename = "sameDevice", default, skip_serializing_if = "Option::is_none")]
        pub same_device: Option<String>,
        #[serde(rename = "webWallet", default, skip_serializing_if = "Option::is_none")]
        pub web_wallet: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qr: Option<String>,
        #[serde(rename = "expiresIn", default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<f64>,
        #[serde(rename = "pollSeconds", default, skip_serializing_if = "Option::is_none")]
        pub poll_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub back: Option<String>,
        #[serde(rename = "backKind", default, skip_serializing_if = "Option::is_none")]
        pub back_kind: Option<Answer200ViewBackKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub heading: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retry: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checks: Option<Vec<Answer200ViewChecksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reissue: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub csrf: Option<String>,
        #[serde(rename = "uiLocales", default, skip_serializing_if = "Option::is_none")]
        pub ui_locales: Option<String>,
        #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
        pub preferred_language: Option<Answer200PreferredLanguage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }
}

/// The Digital Credentials API's answer
pub mod answer_wallet_dc_api {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/wallet/{state}/dc-api";
    pub const OPERATION_ID: &str = "answerWalletDcApi";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyResponseV1 {
        pub protocol: String,
        pub data: serde_json::Value,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyResponse {
        V1(BodyResponseV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response: Option<BodyResponse>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "wait")]
        Wait,
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewChecksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewBackKind {
        #[serde(rename = "portal")]
        Portal,
        #[serde(rename = "screen")]
        Screen,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub heading: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retry: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checks: Option<Vec<Answer200ViewChecksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub back: Option<String>,
        #[serde(rename = "backKind", default, skip_serializing_if = "Option::is_none")]
        pub back_kind: Option<Answer200ViewBackKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reissue: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "expiresIn", default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Whether the wallet has answered, and the sign-in once it has
pub mod wallet_status {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/authn-api/wallet/{state}/status";
    pub const OPERATION_ID: &str = "walletStatus";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_code: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200Next {
        #[serde(rename = "wait")]
        Wait,
        #[serde(rename = "redirect")]
        Redirect,
        #[serde(rename = "mfa")]
        Mfa,
        #[serde(rename = "password-change")]
        PasswordChange,
        #[serde(rename = "home-cell")]
        HomeCell,
        #[serde(rename = "stay")]
        Stay,
        #[serde(rename = "refused")]
        Refused,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200FormMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "POST")]
        Post,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<Answer200FormMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// A request's own parameters, by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200End {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Passkey {
        #[serde(rename = "unknownCredential", default, skip_serializing_if = "Option::is_none")]
        pub unknown_credential: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub autofill: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewChecksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200ViewBackKind {
        #[serde(rename = "portal")]
        Portal,
        #[serde(rename = "screen")]
        Screen,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wallet: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub heading: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retry: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checks: Option<Vec<Answer200ViewChecksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verdict: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub back: Option<String>,
        #[serde(rename = "backKind", default, skip_serializing_if = "Option::is_none")]
        pub back_kind: Option<Answer200ViewBackKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reissue: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<Answer200Next>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub end: Option<Answer200End>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<Answer200Passkey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "expiresIn", default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "answerConsent" => Some(serde_json::from_value::<answer_consent::Body>(value.clone()).map(|_| ())),
        "signOut" => Some(serde_json::from_value::<sign_out::Body>(value.clone()).map(|_| ())),
        "chooseSignOutAccount" => Some(serde_json::from_value::<choose_sign_out_account::Body>(value.clone()).map(|_| ())),
        "spendRecoveryCode" => Some(serde_json::from_value::<spend_recovery_code::Body>(value.clone()).map(|_| ())),
        "spendEmailedLink" => Some(serde_json::from_value::<spend_emailed_link::Body>(value.clone()).map(|_| ())),
        "checkEmailedCode" => Some(serde_json::from_value::<check_emailed_code::Body>(value.clone()).map(|_| ())),
        "sendEmailedFactor" => Some(serde_json::from_value::<send_emailed_factor::Body>(value.clone()).map(|_| ())),
        "checkFactorPassword" => Some(serde_json::from_value::<check_factor_password::Body>(value.clone()).map(|_| ())),
        "registerPostLoginPasskey" => Some(serde_json::from_value::<register_post_login_passkey::Body>(value.clone()).map(|_| ())),
        "skipPostLoginActivity" => Some(serde_json::from_value::<skip_post_login_activity::Body>(value.clone()).map(|_| ())),
        "confirmAppEnrolment" => Some(serde_json::from_value::<confirm_app_enrolment::Body>(value.clone()).map(|_| ())),
        "beginAppEnrolment" => Some(serde_json::from_value::<begin_app_enrolment::Body>(value.clone()).map(|_| ())),
        "beginKeyEnrolment" => Some(serde_json::from_value::<begin_key_enrolment::Body>(value.clone()).map(|_| ())),
        "ignoreOffer" => Some(serde_json::from_value::<ignore_offer::Body>(value.clone()).map(|_| ())),
        "startOver" => Some(serde_json::from_value::<start_over::Body>(value.clone()).map(|_| ())),
        "checkCode" => Some(serde_json::from_value::<check_code::Body>(value.clone()).map(|_| ())),
        "finishPasskeyStep" => Some(serde_json::from_value::<finish_passkey_step::Body>(value.clone()).map(|_| ())),
        "passkeyStepOptions" => Some(serde_json::from_value::<passkey_step_options::Body>(value.clone()).map(|_| ())),
        "changePassword" => Some(serde_json::from_value::<change_password::Body>(value.clone()).map(|_| ())),
        "startOverFromPasswordChange" => Some(serde_json::from_value::<start_over_from_password_change::Body>(value.clone()).map(|_| ())),
        "useAnotherAccount" => Some(serde_json::from_value::<use_another_account::Body>(value.clone()).map(|_| ())),
        "forgetAccount" => Some(serde_json::from_value::<forget_account::Body>(value.clone()).map(|_| ())),
        "selectAccount" => Some(serde_json::from_value::<select_account::Body>(value.clone()).map(|_| ())),
        "continueAnonymously" => Some(serde_json::from_value::<continue_anonymously::Body>(value.clone()).map(|_| ())),
        "cancelSignIn" => Some(serde_json::from_value::<cancel_sign_in::Body>(value.clone()).map(|_| ())),
        "continueWithCertificate" => Some(serde_json::from_value::<continue_with_certificate::Body>(value.clone()).map(|_| ())),
        "signInByEmail" => Some(serde_json::from_value::<sign_in_by_email::Body>(value.clone()).map(|_| ())),
        "signInWithPasskey" => Some(serde_json::from_value::<sign_in_with_passkey::Body>(value.clone()).map(|_| ())),
        "passkeyOptions" => Some(serde_json::from_value::<passkey_options::Body>(value.clone()).map(|_| ())),
        "signInWithPassword" => Some(serde_json::from_value::<sign_in_with_password::Body>(value.clone()).map(|_| ())),
        "startWalletSignIn" => Some(serde_json::from_value::<start_wallet_sign_in::Body>(value.clone()).map(|_| ())),
        "answerWalletDcApi" => Some(serde_json::from_value::<answer_wallet_dc_api::Body>(value.clone()).map(|_| ())),
        "walletStatus" => Some(serde_json::from_value::<wallet_status::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getIndex", 200) => Some(serde_json::from_value::<get_index::Answer200>(value.clone()).map(|_| ())),
        ("getAccounts", 200) => Some(serde_json::from_value::<get_accounts::Answer200>(value.clone()).map(|_| ())),
        ("getConsent", 200) => Some(serde_json::from_value::<get_consent::Answer200>(value.clone()).map(|_| ())),
        ("answerConsent", 200) => Some(serde_json::from_value::<answer_consent::Answer200>(value.clone()).map(|_| ())),
        ("getSignOut", 200) => Some(serde_json::from_value::<get_sign_out::Answer200>(value.clone()).map(|_| ())),
        ("signOut", 200) => Some(serde_json::from_value::<sign_out::Answer200>(value.clone()).map(|_| ())),
        ("getSignOutAccounts", 200) => Some(serde_json::from_value::<get_sign_out_accounts::Answer200>(value.clone()).map(|_| ())),
        ("chooseSignOutAccount", 200) => Some(serde_json::from_value::<choose_sign_out_account::Answer200>(value.clone()).map(|_| ())),
        ("getStep", 200) => Some(serde_json::from_value::<get_step::Answer200>(value.clone()).map(|_| ())),
        ("spendRecoveryCode", 200) => Some(serde_json::from_value::<spend_recovery_code::Answer200>(value.clone()).map(|_| ())),
        ("spendEmailedLink", 200) => Some(serde_json::from_value::<spend_emailed_link::Answer200>(value.clone()).map(|_| ())),
        ("checkEmailedCode", 200) => Some(serde_json::from_value::<check_emailed_code::Answer200>(value.clone()).map(|_| ())),
        ("sendEmailedFactor", 200) => Some(serde_json::from_value::<send_emailed_factor::Answer200>(value.clone()).map(|_| ())),
        ("checkFactorPassword", 200) => Some(serde_json::from_value::<check_factor_password::Answer200>(value.clone()).map(|_| ())),
        ("registerPostLoginPasskey", 200) => Some(serde_json::from_value::<register_post_login_passkey::Answer200>(value.clone()).map(|_| ())),
        ("skipPostLoginActivity", 200) => Some(serde_json::from_value::<skip_post_login_activity::Answer200>(value.clone()).map(|_| ())),
        ("confirmAppEnrolment", 200) => Some(serde_json::from_value::<confirm_app_enrolment::Answer200>(value.clone()).map(|_| ())),
        ("beginAppEnrolment", 200) => Some(serde_json::from_value::<begin_app_enrolment::Answer200>(value.clone()).map(|_| ())),
        ("beginKeyEnrolment", 200) => Some(serde_json::from_value::<begin_key_enrolment::Answer200>(value.clone()).map(|_| ())),
        ("ignoreOffer", 200) => Some(serde_json::from_value::<ignore_offer::Answer200>(value.clone()).map(|_| ())),
        ("startOver", 200) => Some(serde_json::from_value::<start_over::Answer200>(value.clone()).map(|_| ())),
        ("checkCode", 200) => Some(serde_json::from_value::<check_code::Answer200>(value.clone()).map(|_| ())),
        ("finishPasskeyStep", 200) => Some(serde_json::from_value::<finish_passkey_step::Answer200>(value.clone()).map(|_| ())),
        ("passkeyStepOptions", 200) => Some(serde_json::from_value::<passkey_step_options::Answer200>(value.clone()).map(|_| ())),
        ("getOpenApi", 200) => Some(serde_json::from_value::<get_open_api::Answer200>(value.clone()).map(|_| ())),
        ("getPasswordChange", 200) => Some(serde_json::from_value::<get_password_change::Answer200>(value.clone()).map(|_| ())),
        ("changePassword", 200) => Some(serde_json::from_value::<change_password::Answer200>(value.clone()).map(|_| ())),
        ("startOverFromPasswordChange", 200) => Some(serde_json::from_value::<start_over_from_password_change::Answer200>(value.clone()).map(|_| ())),
        ("getScreen", 200) => Some(serde_json::from_value::<get_screen::Answer200>(value.clone()).map(|_| ())),
        ("getAccountChoice", 200) => Some(serde_json::from_value::<get_account_choice::Answer200>(value.clone()).map(|_| ())),
        ("useAnotherAccount", 200) => Some(serde_json::from_value::<use_another_account::Answer200>(value.clone()).map(|_| ())),
        ("forgetAccount", 200) => Some(serde_json::from_value::<forget_account::Answer200>(value.clone()).map(|_| ())),
        ("selectAccount", 200) => Some(serde_json::from_value::<select_account::Answer200>(value.clone()).map(|_| ())),
        ("continueAnonymously", 200) => Some(serde_json::from_value::<continue_anonymously::Answer200>(value.clone()).map(|_| ())),
        ("cancelSignIn", 200) => Some(serde_json::from_value::<cancel_sign_in::Answer200>(value.clone()).map(|_| ())),
        ("continueWithCertificate", 200) => Some(serde_json::from_value::<continue_with_certificate::Answer200>(value.clone()).map(|_| ())),
        ("signInByEmail", 200) => Some(serde_json::from_value::<sign_in_by_email::Answer200>(value.clone()).map(|_| ())),
        ("getPartners", 200) => Some(serde_json::from_value::<get_partners::Answer200>(value.clone()).map(|_| ())),
        ("signInWithPasskey", 200) => Some(serde_json::from_value::<sign_in_with_passkey::Answer200>(value.clone()).map(|_| ())),
        ("passkeyOptions", 200) => Some(serde_json::from_value::<passkey_options::Answer200>(value.clone()).map(|_| ())),
        ("signInWithPassword", 200) => Some(serde_json::from_value::<sign_in_with_password::Answer200>(value.clone()).map(|_| ())),
        ("getWalletStart", 200) => Some(serde_json::from_value::<get_wallet_start::Answer200>(value.clone()).map(|_| ())),
        ("startWalletSignIn", 200) => Some(serde_json::from_value::<start_wallet_sign_in::Answer200>(value.clone()).map(|_| ())),
        ("getWalletWait", 200) => Some(serde_json::from_value::<get_wallet_wait::Answer200>(value.clone()).map(|_| ())),
        ("answerWalletDcApi", 200) => Some(serde_json::from_value::<answer_wallet_dc_api::Answer200>(value.clone()).map(|_| ())),
        ("walletStatus", 200) => Some(serde_json::from_value::<wallet_status::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
