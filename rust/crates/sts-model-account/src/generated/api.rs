// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

pub mod components {
}

/// Lists every operation of this API
pub mod get_index {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api";
    pub const OPERATION_ID: &str = "getIndex";

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
        pub tag: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub access: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub mirrors: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub api: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<Answer200OperationsItem>>,
    }
}

/// The AuthZEN access requests waiting for you to decide
pub mod get_access_requests {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/access-requests";
    pub const OPERATION_ID: &str = "getAccessRequests";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemApproval {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "approvedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub approved_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "approvedUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub approved_until: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub approver: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemApprovers {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub requester: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<Answer200RowsItemClient>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub application: Option<Option<String>>,
        /// An AuthZEN Authorization API 1.0 member as the PEP sent it: its
        /// `properties` and its context are the caller's to define.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<serde_json::Value>,
        /// An AuthZEN Authorization API 1.0 member as the PEP sent it: its
        /// `properties` and its context are the caller's to define.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<serde_json::Value>,
        /// An AuthZEN Authorization API 1.0 member as the PEP sent it: its
        /// `properties` and its context are the caller's to define.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<serde_json::Value>,
        /// An AuthZEN Authorization API 1.0 member as the PEP sent it: its
        /// `properties` and its context are the caller's to define.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub emergency: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub justification: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub finished_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
        pub decided_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approval: Option<Answer200RowsItemApproval>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approvers: Option<Answer200RowsItemApprovers>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// Approves or denies an AuthZEN access request
pub mod decide_access_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/access-requests";
    pub const OPERATION_ID: &str = "decideAccessRequest";

    /// approve or deny.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "approve")]
        Approve,
        #[serde(rename = "deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The access request, from the list.
        pub request: String,
        /// approve or deny.
        pub action: BodyAction,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Checks an activation link and answers the setup form
pub mod get_activation {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/activation";
    pub const OPERATION_ID: &str = "getActivation";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Rules {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PendingOptionsRp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PendingOptionsAuthenticatorSelection {
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
    pub struct Answer200PendingOptions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rp: Option<Answer200PendingOptionsRp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<f64>,
        #[serde(rename = "authenticatorSelection", default, skip_serializing_if = "Option::is_none")]
        pub authenticator_selection: Option<Answer200PendingOptionsAuthenticatorSelection>,
        #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
        pub cred_props: Option<bool>,
        #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none")]
        pub min_pin_length: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hints: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PendingFallback {
        #[serde(rename = "asksPostQuantum", default, skip_serializing_if = "Option::is_none")]
        pub asks_post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classical: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retrying: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Pending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "userHandle", default, skip_serializing_if = "Option::is_none")]
        pub user_handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclude: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Answer200PendingOptions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback: Option<Answer200PendingFallback>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Enrolment {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grouped: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Answer200Rules>,
        #[serde(rename = "webauthnEnabled", default, skip_serializing_if = "Option::is_none")]
        pub webauthn_enabled: Option<bool>,
        #[serde(rename = "passkeyOffered", default, skip_serializing_if = "Option::is_none")]
        pub passkey_offered: Option<bool>,
        #[serde(rename = "passkeyAlone", default, skip_serializing_if = "Option::is_none")]
        pub passkey_alone: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lanes: Option<Vec<String>>,
        #[serde(rename = "totpOffered", default, skip_serializing_if = "Option::is_none")]
        pub totp_offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<bool>,
        #[serde(rename = "secondStep", default, skip_serializing_if = "Option::is_none")]
        pub second_step: Option<bool>,
        #[serde(rename = "wantsTotp", default, skip_serializing_if = "Option::is_none")]
        pub wants_totp: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Answer200Pending>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<Answer200Enrolment>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub warning: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(rename = "withTotp", default, skip_serializing_if = "Option::is_none")]
        pub with_totp: Option<bool>,
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
    }
}

/// Answers one step of an activation
pub mod activate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/activation";
    pub const OPERATION_ID: &str = "activate";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPasskeyV1 {
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
    pub enum BodyPasskey {
        V1(BodyPasskeyV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyRoleV1 {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "primary")]
        Primary,
        #[serde(rename = "mfa")]
        Mfa,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyKeyRole {
        V1(BodyKeyRoleV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTotpV1 {
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
    pub enum BodyTotp {
        V1(BodyTotpV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyStepV1 {
        #[serde(rename = "setup")]
        Setup,
        #[serde(rename = "key")]
        Key,
        #[serde(rename = "totp")]
        Totp,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyStep {
        V1(BodyStepV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKindV1 {
        #[serde(rename = "passkey")]
        Passkey,
        #[serde(rename = "security-key")]
        SecurityKey,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyKind {
        V1(BodyKindV1),
        String(String),
    }

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
        /// The username the link names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// The link's single-use token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        /// `setup`: the password to set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// `setup`: the password again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
        /// `setup`: `1` registers a passkey.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<BodyPasskey>,
        /// Before #1135: `primary` or `mfa` registers a passkey, `none` does not;
        /// `passkey` says the same.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key_role: Option<BodyKeyRole>,
        /// `1`: set up an authenticator app too.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<BodyTotp>,
        /// Which step this answers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<BodyStep>,
        /// `totp`: the code the authenticator app shows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        /// `setup`: where the passkey lives.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKind>,
        /// `setup`: `classical` (the default) or `pqc`, where the realm offers a
        /// post-quantum passkey beside a classical one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<BodyLane>,
        /// `key`: the pending registration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment_id: Option<String>,
        /// `key`: the browser's ceremony result, as JSON.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewRules {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPendingOptionsRp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPendingOptionsAuthenticatorSelection {
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
    pub struct Answer200ViewPendingOptions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rp: Option<Answer200ViewPendingOptionsRp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<f64>,
        #[serde(rename = "authenticatorSelection", default, skip_serializing_if = "Option::is_none")]
        pub authenticator_selection: Option<Answer200ViewPendingOptionsAuthenticatorSelection>,
        #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
        pub cred_props: Option<bool>,
        #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none")]
        pub min_pin_length: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hints: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPendingFallback {
        #[serde(rename = "asksPostQuantum", default, skip_serializing_if = "Option::is_none")]
        pub asks_post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classical: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retrying: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "userHandle", default, skip_serializing_if = "Option::is_none")]
        pub user_handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclude: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Answer200ViewPendingOptions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback: Option<Answer200ViewPendingFallback>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEnrolment {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grouped: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub step: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Answer200ViewRules>,
        #[serde(rename = "webauthnEnabled", default, skip_serializing_if = "Option::is_none")]
        pub webauthn_enabled: Option<bool>,
        #[serde(rename = "passkeyOffered", default, skip_serializing_if = "Option::is_none")]
        pub passkey_offered: Option<bool>,
        #[serde(rename = "passkeyAlone", default, skip_serializing_if = "Option::is_none")]
        pub passkey_alone: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lanes: Option<Vec<String>>,
        #[serde(rename = "totpOffered", default, skip_serializing_if = "Option::is_none")]
        pub totp_offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passkey: Option<bool>,
        #[serde(rename = "secondStep", default, skip_serializing_if = "Option::is_none")]
        pub second_step: Option<bool>,
        #[serde(rename = "wantsTotp", default, skip_serializing_if = "Option::is_none")]
        pub wants_totp: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Answer200ViewPending>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<Answer200ViewEnrolment>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub warning: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(rename = "withTotp", default, skip_serializing_if = "Option::is_none")]
        pub with_totp: Option<bool>,
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Announcements for everybody signed in to the portal
pub mod get_announcements {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/announcements";
    pub const OPERATION_ID: &str = "getAnnouncements";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AnnouncementsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub now: Option<f64>,
        #[serde(rename = "everyMs", default, skip_serializing_if = "Option::is_none")]
        pub every_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub announcements: Option<Vec<Answer200AnnouncementsItem>>,
    }
}

/// Your app passwords, and the doors that need one
pub mod get_app_passwords {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/app-passwords";
    pub const OPERATION_ID: &str = "getAppPasswords";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Doors {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<Vec<String>>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
        pub second_factor: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applies: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DoorTableItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PasswordsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedDoor", default, skip_serializing_if = "Option::is_none")]
        pub last_used_door: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Fresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Answer200Doors>,
        #[serde(rename = "doorTable", default, skip_serializing_if = "Option::is_none")]
        pub door_table: Option<Vec<Answer200DoorTableItem>>,
        /// Each door's label, by its id.
        #[serde(rename = "doorLabels", default, skip_serializing_if = "Option::is_none")]
        pub door_labels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passwords: Option<Vec<Answer200PasswordsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "maxName", default, skip_serializing_if = "Option::is_none")]
        pub max_name: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200Fresh>,
    }
}

/// Makes or revokes one of your app passwords
pub mod change_app_passwords {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/app-passwords";
    pub const OPERATION_ID: &str = "changeAppPasswords";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "create")]
        Create,
        #[serde(rename = "revoke")]
        Revoke,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDoorLdapV1 {
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
    pub enum BodyDoorLdap {
        V1(BodyDoorLdapV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDoorWstrustV1 {
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
    pub enum BodyDoorWstrust {
        V1(BodyDoorWstrustV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDoorScimV1 {
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
    pub enum BodyDoorScim {
        V1(BodyDoorScimV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDoorSsfV1 {
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
    pub enum BodyDoorSsf {
        V1(BodyDoorSsfV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDoorEstV1 {
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
    pub enum BodyDoorEst {
        V1(BodyDoorEstV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `create` makes one; `revoke` ends the one `id` names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// What the new password is for, in your words.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The id of the app password to revoke.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// Accept the new password at the ldap door.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door_ldap: Option<BodyDoorLdap>,
        /// Accept the new password at the wstrust door.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door_wstrust: Option<BodyDoorWstrust>,
        /// Accept the new password at the scim door.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door_scim: Option<BodyDoorScim>,
        /// Accept the new password at the ssf door.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door_ssf: Option<BodyDoorSsf>,
        /// Accept the new password at the est door.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door_est: Option<BodyDoorEst>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDoors {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<Vec<String>>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
        pub second_factor: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applies: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDoorTableItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPasswordsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedDoor", default, skip_serializing_if = "Option::is_none")]
        pub last_used_door: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Answer200ViewDoors>,
        #[serde(rename = "doorTable", default, skip_serializing_if = "Option::is_none")]
        pub door_table: Option<Vec<Answer200ViewDoorTableItem>>,
        /// Each door's label, by its id.
        #[serde(rename = "doorLabels", default, skip_serializing_if = "Option::is_none")]
        pub door_labels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub passwords: Option<Vec<Answer200ViewPasswordsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "maxName", default, skip_serializing_if = "Option::is_none")]
        pub max_name: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200ViewFresh>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The applications you can be signed in to
pub mod get_applications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/applications";
    pub const OPERATION_ID: &str = "getApplications";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemLaunchesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "homePage", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub home_page: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub launchable: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub families: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ways: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub withheld: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub launches: Option<Vec<Answer200RowsItemLaunchesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(rename = "notSignIn", default, skip_serializing_if = "Option::is_none")]
        pub not_sign_in: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scanned: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub truncated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<f64>,
    }
}

/// Replaces your own values of one custom attribute
pub mod set_custom_attribute {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/attributes";
    pub const OPERATION_ID: &str = "setCustomAttribute";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyValues {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The custom attribute's name, one this realm's definition lets you edit
        /// on the portal.
        pub attribute: String,
        /// Every value the attribute is to hold afterwards; none clears it. A
        /// single-valued attribute takes one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<BodyValues>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Your certificates and the enrollment credentials you hold
pub mod get_certificates {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/certificates";
    pub const OPERATION_ID: &str = "getCertificates";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Urls {
        #[serde(rename = "acmeDirectory", default, skip_serializing_if = "Option::is_none")]
        pub acme_directory: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub est: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Fresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(rename = "hmacKey", default, skip_serializing_if = "Option::is_none")]
        pub hmac_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "scepUrl", default, skip_serializing_if = "Option::is_none")]
        pub scep_url: Option<String>,
        #[serde(rename = "plainScepUrl", default, skip_serializing_if = "Option::is_none")]
        pub plain_scep_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolledItemRequestedBy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub admin: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolledItemRevoked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub by: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolledItem {
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
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
        pub requested_by: Option<Answer200EnrolledItemRequestedBy>,
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
        pub revoked: Option<Answer200EnrolledItemRevoked>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AcmeKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
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
    pub struct Answer200Acme {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200AcmeKeysItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Est {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ScepChallengesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub profile: Option<Option<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_by: Option<Option<String>>,
        #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Scep {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenges: Option<Vec<Answer200ScepChallengesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<String>>,
        #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default_profile: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resolved: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
        /// Each enrollment family's label, by its id.
        #[serde(rename = "familyLabels", default, skip_serializing_if = "Option::is_none")]
        pub family_labels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub urls: Option<Answer200Urls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200Fresh>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolled: Option<Vec<Answer200EnrolledItem>>,
        #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
        pub host_names: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acme: Option<Answer200Acme>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub est: Option<Answer200Est>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<Answer200Scep>,
    }
}

/// Makes or deletes an enrollment credential, or revokes a certificate
pub mod change_certificates {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/certificates";
    pub const OPERATION_ID: &str = "changeCertificates";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "create-eab")]
        CreateEab,
        #[serde(rename = "delete-eab")]
        DeleteEab,
        #[serde(rename = "create-challenge")]
        CreateChallenge,
        #[serde(rename = "delete-challenge")]
        DeleteChallenge,
        #[serde(rename = "revoke")]
        Revoke,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProfileV1 {
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
        #[serde(rename = "device")]
        Device,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyProfile {
        V1(BodyProfileV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReasonV1 {
        #[serde(rename = "unspecified")]
        Unspecified,
        #[serde(rename = "keyCompromise")]
        KeyCompromise,
        #[serde(rename = "affiliationChanged")]
        AffiliationChanged,
        #[serde(rename = "superseded")]
        Superseded,
        #[serde(rename = "cessationOfOperation")]
        CessationOfOperation,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyReason {
        V1(BodyReasonV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// What to do.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// The account binding key to delete.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        /// The challenge password to delete.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// The profile a new SCEP challenge is for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<BodyProfile>,
        /// The serial of the certificate to revoke.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        /// The RFC 5280 reason for a revocation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewUrls {
        #[serde(rename = "acmeDirectory", default, skip_serializing_if = "Option::is_none")]
        pub acme_directory: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub est: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(rename = "hmacKey", default, skip_serializing_if = "Option::is_none")]
        pub hmac_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "scepUrl", default, skip_serializing_if = "Option::is_none")]
        pub scep_url: Option<String>,
        #[serde(rename = "plainScepUrl", default, skip_serializing_if = "Option::is_none")]
        pub plain_scep_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEnrolledItemRequestedBy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub admin: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEnrolledItemRevoked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub by: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEnrolledItem {
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
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
        pub requested_by: Option<Answer200ViewEnrolledItemRequestedBy>,
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
        pub revoked: Option<Answer200ViewEnrolledItemRevoked>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewAcmeKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
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
    pub struct Answer200ViewAcme {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200ViewAcmeKeysItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEst {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewScepChallengesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub profile: Option<Option<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_by: Option<Option<String>>,
        #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewScep {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenges: Option<Vec<Answer200ViewScepChallengesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<String>>,
        #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default_profile: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resolved: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
        /// Each enrollment family's label, by its id.
        #[serde(rename = "familyLabels", default, skip_serializing_if = "Option::is_none")]
        pub family_labels: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub urls: Option<Answer200ViewUrls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200ViewFresh>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolled: Option<Vec<Answer200ViewEnrolledItem>>,
        #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
        pub host_names: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acme: Option<Answer200ViewAcme>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub est: Option<Answer200ViewEst>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<Answer200ViewScep>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The sign-in requests waiting for you, and your user code
pub mod get_sign_in_requests {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/ciba";
    pub const OPERATION_ID: &str = "getSignInRequests";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stepup: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gnapstepup: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RequestsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_name: Option<Option<String>>,
        #[serde(rename = "bindingMessage", default, skip_serializing_if = "Option::is_none")]
        pub binding_message: Option<String>,
        #[serde(rename = "requestContext", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub request_context: Option<Option<Vec<serde_json::Value>>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub scope: Option<Option<String>>,
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<Vec<String>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GnapItemRightsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        #[serde(rename = "limitsHtml", default, skip_serializing_if = "Option::is_none")]
        pub limits_html: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reference: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parts: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GnapItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub display: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub declared: Option<bool>,
        #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
        pub requested_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<bool>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rights: Option<Vec<Answer200GnapItemRightsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requests: Option<Vec<Answer200RequestsItem>>,
        #[serde(rename = "hasCode", default, skip_serializing_if = "Option::is_none")]
        pub has_code: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gnap: Option<Vec<Answer200GnapItem>>,
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
    }
}

/// Sets your user code, or answers a request
pub mod answer_sign_in_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/ciba";
    pub const OPERATION_ID: &str = "answerSignInRequest";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "set-code")]
        SetCode,
        #[serde(rename = "clear-code")]
        ClearCode,
        #[serde(rename = "approve")]
        Approve,
        #[serde(rename = "deny")]
        Deny,
        #[serde(rename = "gnap-approve")]
        GnapApprove,
        #[serde(rename = "gnap-deny")]
        GnapDeny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRight {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub action: BodyAction,
        /// The request's id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// Your user code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        /// The GNAP rights ticked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub right: Option<BodyRight>,
        /// Release your identity (GNAP).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// The Claims Providers you can link, and your links
pub mod get_claim_sources {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/claim-sources";
    pub const OPERATION_ID: &str = "getClaimSources";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItemLink {
        #[serde(rename = "linkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub linked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stale: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issuer: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub delivery: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<Answer200ProvidersItemLink>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200ProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub linked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<String>,
    }
}

/// Links or unlinks a Claims Provider
pub mod link_claim_source {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/claim-sources";
    pub const OPERATION_ID: &str = "linkClaimSource";

    /// `link` starts the provider's sign-in; `unlink` removes the link.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "link")]
        Link,
        #[serde(rename = "unlink")]
        Unlink,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `link` starts the provider's sign-in; `unlink` removes the link.
        pub action: BodyAction,
        /// The Claims Provider's id.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
    }
}

/// The consumer providers you can connect, and yours
pub mod get_connected_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/connected-accounts";
    pub const OPERATION_ID: &str = "getConnectedAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub provider: Option<Option<String>>,
        #[serde(rename = "providerLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub provider_label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connected: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200ProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connected: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<String>,
    }
}

/// Connects or disconnects a consumer provider
pub mod connect_account {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/connected-accounts";
    pub const OPERATION_ID: &str = "connectAccount";

    /// `connect` starts the provider's sign-in; `disconnect` removes the
    /// connection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "connect")]
        Connect,
        #[serde(rename = "disconnect")]
        Disconnect,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `connect` starts the provider's sign-in; `disconnect` removes the
        /// connection.
        pub action: BodyAction,
        /// The provider relationship's id.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
    }
}

/// What you have agreed each application may ask for
pub mod get_consents {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/consents";
    pub const OPERATION_ID: &str = "getConsents";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupsItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GroupsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200GroupsItemRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AdministrativeItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AdministrativeItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200AdministrativeItemRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<Answer200GroupsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub administrative: Option<Vec<Answer200AdministrativeItem>>,
    }
}

/// Withdraws a consent of yours
pub mod withdraw_consent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/consents";
    pub const OPERATION_ID: &str = "withdrawConsent";

    /// `scope`: withdraw one scope. `application`: withdraw everything one
    /// application holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "scope")]
        Scope,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `scope`: withdraw one scope. `application`: withdraw everything one
        /// application holds.
        pub action: BodyAction,
        /// The application's client_id.
        pub client: String,
        /// The scope, for `action=scope`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The page of the list the form was on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// The credentials you can put into your own wallet
pub mod get_offerable_credentials {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/credentials/offerable";
    pub const OPERATION_ID: &str = "getOfferableCredentials";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ConfigurationsItemSigningAlgsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ConfigurationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "issuerDid", default, skip_serializing_if = "Option::is_none")]
        pub issuer_did: Option<bool>,
        #[serde(rename = "signingAlgs", default, skip_serializing_if = "Option::is_none")]
        pub signing_algs: Option<Vec<Answer200ConfigurationsItemSigningAlgsItem>>,
        #[serde(rename = "defaultSigningAlg", default, skip_serializing_if = "Option::is_none")]
        pub default_signing_alg: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuedItemCopiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub position: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub of: Option<i64>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(rename = "removedAt", default, skip_serializing_if = "Option::is_none")]
        pub removed_at: Option<String>,
        #[serde(rename = "walletEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet_event: Option<Option<String>>,
        #[serde(rename = "walletEventAt", default, skip_serializing_if = "Option::is_none")]
        pub wallet_event_at: Option<String>,
        #[serde(rename = "keyThumbprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub key_thumbprint: Option<Option<String>>,
        #[serde(rename = "holderDid", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub holder_did: Option<Option<String>>,
        #[serde(rename = "statusIndex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub status_index: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub configuration_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub format: Option<Option<String>>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        /// How many copies are in each status.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(rename = "removedAt", default, skip_serializing_if = "Option::is_none")]
        pub removed_at: Option<String>,
        #[serde(rename = "walletEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet_event: Option<Option<String>>,
        #[serde(rename = "walletEventAt", default, skip_serializing_if = "Option::is_none")]
        pub wallet_event_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub copies: Option<Vec<Answer200IssuedItemCopiesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub length: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode {
        #[serde(rename = "pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub pre_authorized_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tx_code: Option<Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrantsAuthorizationCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer_state: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrants {
        #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub urn_ietf_params_oauth_grant_type_pre_authorized_code: Option<Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorization_code: Option<Answer200OfferCredentialOfferGrantsAuthorizationCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOffer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_configuration_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Answer200OfferCredentialOfferGrants>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferByValue {
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferByReference {
        #[serde(rename = "credentialOfferUri", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer_uri: Option<String>,
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Offer {
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none")]
        pub configuration_id: Option<String>,
        #[serde(rename = "signingAlg", default, skip_serializing_if = "Option::is_none")]
        pub signing_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "credentialOffer", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer: Option<Answer200OfferCredentialOffer>,
        #[serde(rename = "txCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub tx_code: Option<Option<String>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(rename = "byValue", default, skip_serializing_if = "Option::is_none")]
        pub by_value: Option<Answer200OfferByValue>,
        #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
        pub by_reference: Option<Answer200OfferByReference>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub configurations: Option<Vec<Answer200ConfigurationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub modes: Option<Vec<String>>,
        #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet: Option<Option<String>>,
        #[serde(rename = "batchSize", default, skip_serializing_if = "Option::is_none")]
        pub batch_size: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Vec<Answer200IssuedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offer: Option<Answer200Offer>,
    }
}

/// Makes a Credential Offer for your own wallet
pub mod create_credential_offer {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/credentials/offers";
    pub const OPERATION_ID: &str = "createCredentialOffer";

    /// `cross-device` (Appendix H.2: issued as soon as the wallet asks) or
    /// `deferred` (H.3: the credential endpoint answers a `transaction_id` first).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMode {
        #[serde(rename = "cross-device")]
        CrossDevice,
        #[serde(rename = "deferred")]
        Deferred,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `credential_configuration_id` to offer, one of `GET
        /// /account-api/credentials/offerable`'s.
        pub configuration: String,
        /// `cross-device` (Appendix H.2: issued as soon as the wallet asks) or
        /// `deferred` (H.3: the credential endpoint answers a `transaction_id`
        /// first).
        pub mode: BodyMode,
        /// The algorithm the credential is signed with, one of the configuration's
        /// `signingAlgs`; left out or empty, the configured
        /// `oid4vci.credentialSigningAlgorithm`.
        #[serde(rename = "signingAlg", default, skip_serializing_if = "Option::is_none")]
        pub signing_alg: Option<String>,
        /// Which page of `issued`, newest first. Clamped to the last.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub length: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode {
        #[serde(rename = "pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub pre_authorized_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tx_code: Option<Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrantsAuthorizationCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer_state: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOfferGrants {
        #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub urn_ietf_params_oauth_grant_type_pre_authorized_code: Option<Answer200OfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorization_code: Option<Answer200OfferCredentialOfferGrantsAuthorizationCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferCredentialOffer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_configuration_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Answer200OfferCredentialOfferGrants>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferByValue {
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OfferByReference {
        #[serde(rename = "credentialOfferUri", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer_uri: Option<String>,
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Offer {
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none")]
        pub configuration_id: Option<String>,
        #[serde(rename = "signingAlg", default, skip_serializing_if = "Option::is_none")]
        pub signing_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "credentialOffer", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer: Option<Answer200OfferCredentialOffer>,
        #[serde(rename = "txCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub tx_code: Option<Option<String>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(rename = "byValue", default, skip_serializing_if = "Option::is_none")]
        pub by_value: Option<Answer200OfferByValue>,
        #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
        pub by_reference: Option<Answer200OfferByReference>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewConfigurationsItemSigningAlgsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewConfigurationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "issuerDid", default, skip_serializing_if = "Option::is_none")]
        pub issuer_did: Option<bool>,
        #[serde(rename = "signingAlgs", default, skip_serializing_if = "Option::is_none")]
        pub signing_algs: Option<Vec<Answer200ViewConfigurationsItemSigningAlgsItem>>,
        #[serde(rename = "defaultSigningAlg", default, skip_serializing_if = "Option::is_none")]
        pub default_signing_alg: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewIssuedItemCopiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub position: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub of: Option<i64>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(rename = "removedAt", default, skip_serializing_if = "Option::is_none")]
        pub removed_at: Option<String>,
        #[serde(rename = "walletEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet_event: Option<Option<String>>,
        #[serde(rename = "walletEventAt", default, skip_serializing_if = "Option::is_none")]
        pub wallet_event_at: Option<String>,
        #[serde(rename = "keyThumbprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub key_thumbprint: Option<Option<String>>,
        #[serde(rename = "holderDid", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub holder_did: Option<Option<String>>,
        #[serde(rename = "statusIndex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub status_index: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewIssuedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub configuration_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub format: Option<Option<String>>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        /// How many copies are in each status.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(rename = "removedAt", default, skip_serializing_if = "Option::is_none")]
        pub removed_at: Option<String>,
        #[serde(rename = "walletEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet_event: Option<Option<String>>,
        #[serde(rename = "walletEventAt", default, skip_serializing_if = "Option::is_none")]
        pub wallet_event_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub copies: Option<Vec<Answer200ViewIssuedItemCopiesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub length: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode {
        #[serde(rename = "pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub pre_authorized_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tx_code: Option<Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrantsAuthorizationCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer_state: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrants {
        #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub urn_ietf_params_oauth_grant_type_pre_authorized_code: Option<Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorization_code: Option<Answer200ViewOfferCredentialOfferGrantsAuthorizationCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOffer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_configuration_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Answer200ViewOfferCredentialOfferGrants>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferByValue {
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferByReference {
        #[serde(rename = "credentialOfferUri", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer_uri: Option<String>,
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOffer {
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none")]
        pub configuration_id: Option<String>,
        #[serde(rename = "signingAlg", default, skip_serializing_if = "Option::is_none")]
        pub signing_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "credentialOffer", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer: Option<Answer200ViewOfferCredentialOffer>,
        #[serde(rename = "txCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub tx_code: Option<Option<String>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(rename = "byValue", default, skip_serializing_if = "Option::is_none")]
        pub by_value: Option<Answer200ViewOfferByValue>,
        #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
        pub by_reference: Option<Answer200ViewOfferByReference>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub configurations: Option<Vec<Answer200ViewConfigurationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub modes: Option<Vec<String>>,
        #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet: Option<Option<String>>,
        #[serde(rename = "batchSize", default, skip_serializing_if = "Option::is_none")]
        pub batch_size: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Vec<Answer200ViewIssuedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200ViewPaging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offer: Option<Answer200ViewOffer>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offer: Option<Answer200Offer>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Removes a credential issued to you: every copy, or one
pub mod remove_issued_credential {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/credentials/remove";
    pub const OPERATION_ID: &str = "removeIssuedCredential";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An issuance's `id`, from `issued` in `GET
        /// /account-api/credentials/offerable`, which removes every copy of it; or
        /// one copy's, from its `copies`, which removes that copy alone.
        pub id: String,
        /// Which page of `issued`, newest first. Clamped to the last.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewConfigurationsItemSigningAlgsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewConfigurationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "issuerDid", default, skip_serializing_if = "Option::is_none")]
        pub issuer_did: Option<bool>,
        #[serde(rename = "signingAlgs", default, skip_serializing_if = "Option::is_none")]
        pub signing_algs: Option<Vec<Answer200ViewConfigurationsItemSigningAlgsItem>>,
        #[serde(rename = "defaultSigningAlg", default, skip_serializing_if = "Option::is_none")]
        pub default_signing_alg: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewIssuedItemCopiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub position: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub of: Option<i64>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(rename = "removedAt", default, skip_serializing_if = "Option::is_none")]
        pub removed_at: Option<String>,
        #[serde(rename = "walletEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet_event: Option<Option<String>>,
        #[serde(rename = "walletEventAt", default, skip_serializing_if = "Option::is_none")]
        pub wallet_event_at: Option<String>,
        #[serde(rename = "keyThumbprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub key_thumbprint: Option<Option<String>>,
        #[serde(rename = "holderDid", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub holder_did: Option<Option<String>>,
        #[serde(rename = "statusIndex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub status_index: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewIssuedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub configuration_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub format: Option<Option<String>>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        /// How many copies are in each status.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removable: Option<bool>,
        #[serde(rename = "removedAt", default, skip_serializing_if = "Option::is_none")]
        pub removed_at: Option<String>,
        #[serde(rename = "walletEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet_event: Option<Option<String>>,
        #[serde(rename = "walletEventAt", default, skip_serializing_if = "Option::is_none")]
        pub wallet_event_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub copies: Option<Vec<Answer200ViewIssuedItemCopiesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub input_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub length: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode {
        #[serde(rename = "pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub pre_authorized_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tx_code: Option<Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrantsAuthorizationCode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer_state: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOfferGrants {
        #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code", default, skip_serializing_if = "Option::is_none")]
        pub urn_ietf_params_oauth_grant_type_pre_authorized_code: Option<Answer200ViewOfferCredentialOfferGrantsUrnIetfParamsOauthGrantTypePreAuthorizedCode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorization_code: Option<Answer200ViewOfferCredentialOfferGrantsAuthorizationCode>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferCredentialOffer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_configuration_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Answer200ViewOfferCredentialOfferGrants>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferByValue {
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOfferByReference {
        #[serde(rename = "credentialOfferUri", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer_uri: Option<String>,
        #[serde(rename = "offerUri", default, skip_serializing_if = "Option::is_none")]
        pub offer_uri: Option<String>,
        #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
        pub wallet_url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewOffer {
        #[serde(rename = "configurationId", default, skip_serializing_if = "Option::is_none")]
        pub configuration_id: Option<String>,
        #[serde(rename = "signingAlg", default, skip_serializing_if = "Option::is_none")]
        pub signing_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "credentialOffer", default, skip_serializing_if = "Option::is_none")]
        pub credential_offer: Option<Answer200ViewOfferCredentialOffer>,
        #[serde(rename = "txCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub tx_code: Option<Option<String>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(rename = "byValue", default, skip_serializing_if = "Option::is_none")]
        pub by_value: Option<Answer200ViewOfferByValue>,
        #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
        pub by_reference: Option<Answer200ViewOfferByReference>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub configurations: Option<Vec<Answer200ViewConfigurationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub modes: Option<Vec<String>>,
        #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub wallet: Option<Option<String>>,
        #[serde(rename = "batchSize", default, skip_serializing_if = "Option::is_none")]
        pub batch_size: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Vec<Answer200ViewIssuedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200ViewPaging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offer: Option<Answer200ViewOffer>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removed: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Who may act for you
pub mod get_delegate {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/delegate";
    pub const OPERATION_ID: &str = "getDelegate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Delegate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
        pub may_act: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegate: Option<Answer200Delegate>,
        #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
        pub not_delegated: Option<bool>,
    }
}

/// Names, or clears, who may act for you
pub mod set_delegate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/delegate";
    pub const OPERATION_ID: &str = "setDelegate";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "set")]
        Set,
        #[serde(rename = "clear")]
        Clear,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `set` names the delegate; `clear` removes it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// The DN of a person or an application in this realm, for `action=set`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegate: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Finds people you may name, by part of their username
pub mod find_delegate_candidates {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/delegate/candidates";
    pub const OPERATION_ID: &str = "findDelegateCandidates";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub q: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PeopleItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<String>,
        /// At most ten.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<Vec<Answer200PeopleItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub more: Option<bool>,
    }
}

/// The device request a user code brings up
pub mod get_device_request {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/device";
    pub const OPERATION_ID: &str = "getDeviceRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user_code: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Record {
        #[serde(rename = "userCode", default, skip_serializing_if = "Option::is_none")]
        pub user_code: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none")]
        pub client_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub typed: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub record: Option<Answer200Record>,
    }
}

/// Approves or denies a device sign-in
pub mod answer_device_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/device";
    pub const OPERATION_ID: &str = "answerDeviceRequest";

    /// `approve` signs you in on the device; `deny` refuses it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "approve")]
        Approve,
        #[serde(rename = "deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `approve` signs you in on the device; `deny` refuses it.
        pub action: BodyAction,
        /// The code the device shows.
        pub user_code: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Your devices, and how to register one
pub mod get_devices {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/devices";
    pub const OPERATION_ID: &str = "getDevices";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItemKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<Vec<String>>,
        #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
        pub native_sso: Option<bool>,
        #[serde(rename = "sessionLive", default, skip_serializing_if = "Option::is_none")]
        pub session_live: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200DevicesItemKeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<String>,
        #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Proof {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LinkingOptions {
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
    pub struct Answer200Linking {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Answer200LinkingOptions>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LinkKeysItem {
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trusted: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Link {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolled: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200LinkKeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roaming: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub devices: Option<Vec<Answer200DevicesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platforms: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proof: Option<Answer200Proof>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<String>,
        #[serde(rename = "proofTyp", default, skip_serializing_if = "Option::is_none")]
        pub proof_typ: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub linking: Option<Answer200Linking>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<Answer200Link>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remember: Option<bool>,
    }
}

/// Registers, links, remembers or removes a device
pub mod act_on_devices {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/devices";
    pub const OPERATION_ID: &str = "actOnDevices";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "remove")]
        Remove,
        #[serde(rename = "challenge")]
        Challenge,
        #[serde(rename = "prove")]
        Prove,
        #[serde(rename = "cancel-proof")]
        CancelProof,
        #[serde(rename = "link-begin")]
        LinkBegin,
        #[serde(rename = "link-finish")]
        LinkFinish,
        #[serde(rename = "link-cancel")]
        LinkCancel,
        #[serde(rename = "remember-browser")]
        RememberBrowser,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// What to do; `remove` where none is named.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// `remove`: the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// `prove`, `link-finish`: the challenge being answered.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        /// `prove`: the device-key-proof+jwt JWS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proof: Option<String>,
        /// `prove`: an App Attest key id, beside its object.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub app_attest_key_id: Option<String>,
        /// `prove`: an App Attest attestation object.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub app_attest_object: Option<String>,
        /// `prove`, `link-begin`: an existing device to add the key to; a new
        /// device where empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<String>,
        /// `link-begin`: the passkey (built into this device) to link.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        /// `link-finish`: the WebAuthn assertion, as JSON.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
        /// The device's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// `prove`: the key's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key_label: Option<String>,
        /// The device's platform.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        /// The device's model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        /// The device's operating system.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// A key-proof challenge, for a device app
pub mod device_challenge {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/devices/challenge";
    pub const OPERATION_ID: &str = "deviceChallenge";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// What the challenge is for; `key`, the only one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub typ: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proof_endpoint: Option<String>,
    }
}

/// A device app's key proof
pub mod device_proof {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/devices/proof";
    pub const OPERATION_ID: &str = "deviceProof";

    /// Or an Apple App Attest key and object.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BodyAppAttest {
        pub key_id: String,
        pub attestation: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The challenge `devices/challenge` issued.
        pub challenge: String,
        /// The device-key-proof+jwt JWS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proof: Option<String>,
        /// Or an Apple App Attest key and object.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub app_attest: Option<BodyAppAttest>,
        /// An existing device of yours to add the key to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceKeysItemAttestationRevocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
        pub list_version: Option<String>,
        #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
        pub checked_at: Option<String>,
        #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
        pub chain_serials: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceKeysItemAttestationFreshness {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceKeysItemAttestation {
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
        pub revocation: Option<Answer200DeviceKeysItemAttestationRevocation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub freshness: Option<Answer200DeviceKeysItemAttestationFreshness>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceKeysItemMaterial {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        /// A public JWK as the device presented it (RFC 7517): its members depend
        /// on its key type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwk: Option<serde_json::Value>,
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attachment: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeviceKeysItem {
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
        pub attestation: Option<Answer200DeviceKeysItemAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub material: Option<Answer200DeviceKeysItemMaterial>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
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
    pub struct Answer200DeviceRiskChange {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
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
        pub keys: Option<Vec<Answer200DeviceKeysItem>>,
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
        pub risk_change: Option<Answer200DeviceRiskChange>,
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
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeyAttestationRevocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
        pub list_version: Option<String>,
        #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
        pub checked_at: Option<String>,
        #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
        pub chain_serials: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeyAttestationFreshness {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeyAttestation {
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
        pub revocation: Option<Answer200KeyAttestationRevocation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub freshness: Option<Answer200KeyAttestationFreshness>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeyMaterial {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        /// A public JWK as the device presented it (RFC 7517): its members depend
        /// on its key type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwk: Option<serde_json::Value>,
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attachment: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Key {
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
        pub attestation: Option<Answer200KeyAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub material: Option<Answer200KeyMaterial>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<Answer200Device>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<Answer200Key>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceKeysItemAttestationRevocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
        pub list_version: Option<String>,
        #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
        pub checked_at: Option<String>,
        #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
        pub chain_serials: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceKeysItemAttestationFreshness {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceKeysItemAttestation {
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
        pub revocation: Option<Answer201DeviceKeysItemAttestationRevocation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub freshness: Option<Answer201DeviceKeysItemAttestationFreshness>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceKeysItemMaterial {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        /// A public JWK as the device presented it (RFC 7517): its members depend
        /// on its key type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwk: Option<serde_json::Value>,
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attachment: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceKeysItem {
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
        pub attestation: Option<Answer201DeviceKeysItemAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub material: Option<Answer201DeviceKeysItemMaterial>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceAttestation {
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
    pub struct Answer201DeviceComplianceChange {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
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
    pub struct Answer201DeviceStatusChange {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
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
    pub struct Answer201DeviceRiskChange {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
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

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceEnrolment {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201DeviceRememberedBrowser {
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
    pub struct Answer201Device {
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
        pub keys: Option<Vec<Answer201DeviceKeysItem>>,
        #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
        pub key_kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<Answer201DeviceAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compliance: Option<String>,
        #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
        pub compliance_change: Option<Answer201DeviceComplianceChange>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
        pub status_change: Option<Answer201DeviceStatusChange>,
        #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
        pub risk_level: Option<String>,
        #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
        pub risk_change: Option<Answer201DeviceRiskChange>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub platform: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment: Option<Answer201DeviceEnrolment>,
        #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
        pub native_sso: Option<bool>,
        #[serde(rename = "rememberedBrowser", default, skip_serializing_if = "Option::is_none")]
        pub remembered_browser: Option<Answer201DeviceRememberedBrowser>,
        #[serde(rename = "sessionLive", default, skip_serializing_if = "Option::is_none")]
        pub session_live: Option<bool>,
        #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none")]
        pub last_used: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201KeyAttestationRevocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
        pub list_version: Option<String>,
        #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
        pub checked_at: Option<String>,
        #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
        pub chain_serials: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201KeyAttestationFreshness {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201KeyAttestation {
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
        pub revocation: Option<Answer201KeyAttestationRevocation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub freshness: Option<Answer201KeyAttestationFreshness>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201KeyMaterial {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        /// A public JWK as the device presented it (RFC 7517): its members depend
        /// on its key type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwk: Option<serde_json::Value>,
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attachment: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201Key {
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
        pub attestation: Option<Answer201KeyAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub material: Option<Answer201KeyMaterial>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer201 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub device: Option<Answer201Device>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<Answer201Key>,
    }
}

/// Your email address, its messages, and what was sent
pub mod get_email {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/email";
    pub const OPERATION_ID: &str = "getEmail";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "sentPage", default, skip_serializing_if = "Option::is_none")]
        pub sent_page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CategoriesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub optional: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sent: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200SentItemTo {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SentItem {
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub to: Option<Option<Answer200SentItemTo>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub state: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SentPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub changing: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub categories: Option<Vec<Answer200CategoriesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sent: Option<Vec<Answer200SentItem>>,
        #[serde(rename = "sentPaging", default, skip_serializing_if = "Option::is_none")]
        pub sent_paging: Option<Answer200SentPaging>,
    }
}

/// Verifies your address, changes it, or saves your choices
pub mod post_email {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/email";
    pub const OPERATION_ID: &str = "postEmail";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "verify")]
        Verify,
        #[serde(rename = "preferences")]
        Preferences,
        #[serde(rename = "change")]
        Change,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyNotificationV1 {
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
    pub enum BodyNotification {
        V1(BodyNotificationV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `verify` sends a link to the address on your entry; `change` sends one
        /// to `address`; `preferences` saves `notification`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// The new address, for `change`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        /// `on` to be sent notifications, for `preferences`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notification: Option<BodyNotification>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Whether a forgotten password can be reset here, and how
pub mod get_forgot_password {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/forgot-password";
    pub const OPERATION_ID: &str = "getForgotPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "threeFields", default, skip_serializing_if = "Option::is_none")]
        pub three_fields: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(rename = "tooMany", default, skip_serializing_if = "Option::is_none")]
        pub too_many: Option<String>,
        #[serde(rename = "notOffered", default, skip_serializing_if = "Option::is_none")]
        pub not_offered: Option<String>,
    }
}

/// Asks for a password reset link
pub mod request_password_reset {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/forgot-password";
    pub const OPERATION_ID: &str = "requestPasswordReset";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Your username, or the address on your account.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub account: Option<String>,
        /// The address on your account, where a recovery code is asked for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        /// One of your recovery codes, where one is asked for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(rename = "threeFields", default, skip_serializing_if = "Option::is_none")]
        pub three_fields: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(rename = "tooMany", default, skip_serializing_if = "Option::is_none")]
        pub too_many: Option<String>,
        #[serde(rename = "notOffered", default, skip_serializing_if = "Option::is_none")]
        pub not_offered: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The GNAP grants you gave
pub mod get_gnap_grants {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/gnap";
    pub const OPERATION_ID: &str = "getGnapGrants";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemFinalization {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemTokensItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub format: Option<Option<String>>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bearer: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub access: Option<Vec<serde_json::Value>>,
        #[serde(rename = "revokedWhy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_why: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub finalization: Option<Answer200RowsItemFinalization>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client: Option<Option<String>>,
        #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_name: Option<Option<String>>,
        #[serde(rename = "authorizationServer", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub authorization_server: Option<Option<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "grantExpiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub grant_expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "approvedBy", default, skip_serializing_if = "Option::is_none")]
        pub approved_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rights: Option<Vec<serde_json::Value>>,
        #[serde(rename = "rightsAre", default, skip_serializing_if = "Option::is_none")]
        pub rights_are: Option<String>,
        #[serde(rename = "subjectReleasedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject_released_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub derived_from: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tokens: Option<Vec<Answer200RowsItemTokensItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revocable: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
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
    pub struct Answer200Cells {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cells: Option<Answer200Cells>,
    }
}

/// Revokes a GNAP grant you gave
pub mod revoke_gnap_grant {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/gnap";
    pub const OPERATION_ID: &str = "revokeGnapGrant";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The grant to end, from the list.
        pub grant: String,
        /// The page of the list the form was on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Your Kerberos principal and its keys
pub mod get_kerberos {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/kerberos";
    pub const OPERATION_ID: &str = "getKerberos";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysEtypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Keys {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kvno: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<Answer200KeysEtypesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Made {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kvno: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keytab: Option<String>,
        #[serde(rename = "keytabFilename", default, skip_serializing_if = "Option::is_none")]
        pub keytab_filename: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kdc: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub person: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(rename = "productKdc", default, skip_serializing_if = "Option::is_none")]
        pub product_kdc: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Answer200Keys>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub made: Option<Answer200Made>,
    }
}

/// Makes you a keytab from your own password
pub mod make_keytab {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/kerberos";
    pub const OPERATION_ID: &str = "makeKeytab";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `keytab`, the one thing this page does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// Your password: the keytab is derived from it, and it re-proves you.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewKeysEtypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewKeys {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kvno: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<Answer200ViewKeysEtypesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewMade {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kvno: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keytab: Option<String>,
        #[serde(rename = "keytabFilename", default, skip_serializing_if = "Option::is_none")]
        pub keytab_filename: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kdc: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub person: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(rename = "productKdc", default, skip_serializing_if = "Option::is_none")]
        pub product_kdc: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Answer200ViewKeys>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub made: Option<Answer200ViewMade>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Your passkeys, and adding one
pub mod get_keys {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/keys";
    pub const OPERATION_ID: &str = "getKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysItemAlgorithm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub insecure: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysItemUpgrade {
        #[serde(rename = "upgradedAt", default, skip_serializing_if = "Option::is_none")]
        pub upgraded_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "previousAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub previous_algorithm: Option<String>,
        #[serde(rename = "previousCredentialId", default, skip_serializing_if = "Option::is_none")]
        pub previous_credential_id: Option<String>,
        #[serde(rename = "upgradedTo", default, skip_serializing_if = "Option::is_none")]
        pub upgraded_to: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysItemPossiblyReplaced {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysItemAttestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trusted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub model: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(rename = "androidStatus", default, skip_serializing_if = "Option::is_none")]
        pub android_status: Option<String>,
        #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none")]
        pub device_serial: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysItem {
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub enrolled_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "syncedRefused", default, skip_serializing_if = "Option::is_none")]
        pub synced_refused: Option<bool>,
        #[serde(rename = "attestationRefused", default, skip_serializing_if = "Option::is_none")]
        pub attestation_refused: Option<String>,
        #[serde(rename = "pinRefused", default, skip_serializing_if = "Option::is_none")]
        pub pin_refused: Option<String>,
        #[serde(rename = "postQuantumRefused", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_refused: Option<bool>,
        #[serde(rename = "backupEligible", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub backup_eligible: Option<Option<bool>>,
        #[serde(rename = "backupState", default, skip_serializing_if = "Option::is_none")]
        pub backup_state: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transports: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(rename = "withoutUsername", default, skip_serializing_if = "Option::is_none")]
        pub without_username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<Answer200KeysItemAlgorithm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub upgrade: Option<Answer200KeysItemUpgrade>,
        #[serde(rename = "possiblyReplaced", default, skip_serializing_if = "Option::is_none")]
        pub possibly_replaced: Option<Answer200KeysItemPossiblyReplaced>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<Answer200KeysItemAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolPendingOptionsRp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolPendingOptionsAuthenticatorSelection {
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
    pub struct Answer200EnrolPendingOptions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rp: Option<Answer200EnrolPendingOptionsRp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<f64>,
        #[serde(rename = "authenticatorSelection", default, skip_serializing_if = "Option::is_none")]
        pub authenticator_selection: Option<Answer200EnrolPendingOptionsAuthenticatorSelection>,
        #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
        pub cred_props: Option<bool>,
        #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none")]
        pub min_pin_length: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hints: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolPendingFallback {
        #[serde(rename = "asksPostQuantum", default, skip_serializing_if = "Option::is_none")]
        pub asks_post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classical: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retrying: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EnrolPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "userHandle", default, skip_serializing_if = "Option::is_none")]
        pub user_handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclude: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<Answer200EnrolPendingOptions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback: Option<Answer200EnrolPendingFallback>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Enrol {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
        #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
        pub at_cap: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Answer200EnrolPending>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lanes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignalsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
        pub rp_id: Option<String>,
        #[serde(rename = "userId", default, skip_serializing_if = "Option::is_none")]
        pub user_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accepted: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
        pub mfa_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200KeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrol: Option<Answer200Enrol>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Vec<Answer200SignalsItem>>,
    }
}

/// Begins, finishes or cancels adding a passkey
pub mod enrol_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/keys";
    pub const OPERATION_ID: &str = "enrolKey";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "begin")]
        Begin,
        #[serde(rename = "finish")]
        Finish,
        #[serde(rename = "cancel")]
        Cancel,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRoleV1 {
        #[serde(rename = "primary")]
        Primary,
        #[serde(rename = "mfa")]
        Mfa,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRole {
        V1(BodyRoleV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKindV1 {
        #[serde(rename = "passkey")]
        Passkey,
        #[serde(rename = "security-key")]
        SecurityKey,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyKind {
        V1(BodyKindV1),
        String(String),
    }

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
        /// `begin` mints a challenge, `finish` answers it, `cancel` drops it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// Ignored since #1135: a passkey carries no role.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<BodyRole>,
        /// `begin`: which call to action was pressed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKind>,
        /// `begin`: `classical` (the default) or `pqc`, where the realm offers a
        /// post-quantum passkey beside a classical one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<BodyLane>,
        /// `begin`: `classical` retries with the classical algorithms only, where
        /// `enrol.pending.fallback.classical` says the realm allows it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<String>,
        /// `finish`: the pending enrolment the ceremony answers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolment_id: Option<String>,
        /// `finish`: the browser's ceremony result, as JSON.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Removes one of your passkeys
pub mod remove_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/keys/remove";
    pub const OPERATION_ID: &str = "removeKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// One of your own passkeys.
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
        pub sessions_ended: Option<i64>,
    }
}

/// Renames one of your passkeys
pub mod rename_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/keys/rename";
    pub const OPERATION_ID: &str = "renameKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// One of your own passkeys.
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        /// Its new name; empty puts the default back.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Sets or removes your preferred language
pub mod set_language {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/language";
    pub const OPERATION_ID: &str = "setLanguage";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A BCP 47 tag this service has a catalog for, or empty to follow the
        /// browser.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lang: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// The language data a page for nobody is drawn with
pub mod get_locale {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/locale";
    pub const OPERATION_ID: &str = "getLocale";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200LocaleNegotiatedDirection {
        #[serde(rename = "ltr")]
        Ltr,
        #[serde(rename = "rtl")]
        Rtl,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LocaleNegotiated {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locale: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalog: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub direction: Option<Answer200LocaleNegotiatedDirection>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LocaleOfferedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Locale {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub negotiated: Option<Answer200LocaleNegotiated>,
        /// Each catalog along the chain, by language tag.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogs: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<Vec<Answer200LocaleOfferedItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Version {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(rename = "buildInfo", default, skip_serializing_if = "Option::is_none")]
        pub build_info: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locale: Option<Answer200Locale>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<Answer200Version>,
    }
}

/// Who is signed in, and what every page is drawn with
pub mod get_me {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/me";
    pub const OPERATION_ID: &str = "getMe";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200User {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub photo: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Realm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prefix: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200LocaleNegotiatedDirection {
        #[serde(rename = "ltr")]
        Ltr,
        #[serde(rename = "rtl")]
        Rtl,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LocaleNegotiated {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locale: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalog: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub direction: Option<Answer200LocaleNegotiatedDirection>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LocaleOfferedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Locale {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub negotiated: Option<Answer200LocaleNegotiated>,
        /// Each catalog along the chain, by language tag.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogs: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<Vec<Answer200LocaleOfferedItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Version {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(rename = "buildInfo", default, skip_serializing_if = "Option::is_none")]
        pub build_info: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<Answer200User>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200Realm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locale: Option<Answer200Locale>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<Answer200Version>,
    }
}

/// Your authenticator app, emailed factor and recovery codes
pub mod get_mfa {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/mfa";
    pub const OPERATION_ID: &str = "getMfa";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TotpDetail {
        #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub enrolled_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Totp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<Answer200TotpDetail>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub digits: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub period: Option<Option<f64>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Doors {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applies: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Setup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grouped: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EmailFactorAllowed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EmailFactorOffered {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EmailFactor {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<Answer200EmailFactorAllowed>,
        #[serde(rename = "optedIn", default, skip_serializing_if = "Option::is_none")]
        pub opted_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<Answer200EmailFactorOffered>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub masked: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Codes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub count: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub length: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub advised: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub generated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Fresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replacing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<Answer200Totp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Answer200Doors>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setup: Option<Answer200Setup>,
        #[serde(rename = "emailFactor", default, skip_serializing_if = "Option::is_none")]
        pub email_factor: Option<Answer200EmailFactor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codes: Option<Answer200Codes>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200Fresh>,
    }
}

/// Sets up, confirms or removes your second factors
pub mod change_mfa {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/mfa";
    pub const OPERATION_ID: &str = "changeMfa";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "start")]
        Start,
        #[serde(rename = "confirm")]
        Confirm,
        #[serde(rename = "remove")]
        Remove,
        #[serde(rename = "generate-codes")]
        GenerateCodes,
        #[serde(rename = "confirm-codes")]
        ConfirmCodes,
        #[serde(rename = "discard-codes")]
        DiscardCodes,
        #[serde(rename = "email-factor-on")]
        EmailFactorOn,
        #[serde(rename = "email-factor-off")]
        EmailFactorOff,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKindV1 {
        #[serde(rename = "code")]
        Code,
        #[serde(rename = "link")]
        Link,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyKind {
        V1(BodyKindV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The step: `start` an authenticator app, `confirm` it with a code,
        /// `remove` it; `generate-codes`, `confirm-codes` or `discard-codes` a set
        /// of recovery codes; `email-factor-on` or `email-factor-off`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// For `email-factor-on`: a mailed `code` or a sign-in `link`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKind>,
        /// For `confirm`: the code the app shows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        /// For `confirm-codes` and `discard-codes`: the pending set's handle, from
        /// `generate-codes`'s answer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTotpDetail {
        #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub enrolled_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTotp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<Answer200ViewTotpDetail>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub digits: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub period: Option<Option<f64>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewDoors {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applies: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSetup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grouped: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qr: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digits: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEmailFactorAllowed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEmailFactorOffered {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub link: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewEmailFactor {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<Answer200ViewEmailFactorAllowed>,
        #[serde(rename = "optedIn", default, skip_serializing_if = "Option::is_none")]
        pub opted_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<Answer200ViewEmailFactorOffered>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub masked: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewCodes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub count: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub length: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub advised: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub generated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub replacing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
        pub verifies_credentials: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<Answer200ViewTotp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Answer200ViewDoors>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setup: Option<Answer200ViewSetup>,
        #[serde(rename = "emailFactor", default, skip_serializing_if = "Option::is_none")]
        pub email_factor: Option<Answer200ViewEmailFactor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codes: Option<Answer200ViewCodes>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200ViewFresh>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
        #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
        pub sessions_ended: Option<i64>,
    }
}

/// This API's OpenAPI 3.1 document
pub mod get_open_api {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/openapi.json";
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
        /// The inside of an OpenAPI document (its paths and components): a
        /// statement about this API in OpenAPI's own vocabulary, whose every model
        /// is stated at the operation it describes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<serde_json::Value>,
        /// The inside of an OpenAPI document (its paths and components): a
        /// statement about this API in OpenAPI's own vocabulary, whose every model
        /// is stated at the operation it describes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub components: Option<serde_json::Value>,
    }
}

/// Who you are, this session, and how you sign in
pub mod get_overview {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/overview";
    pub const OPERATION_ID: &str = "getOverview";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Entry {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Session {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignOnDeviceBound {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bound: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fact: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignOn {
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
        pub started_at: Option<f64>,
        #[serde(rename = "authTime", default, skip_serializing_if = "Option::is_none")]
        pub auth_time: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub amr: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        #[serde(rename = "deviceBound", default, skip_serializing_if = "Option::is_none")]
        pub device_bound: Option<Answer200SignOnDeviceBound>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DirectoryClassesItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ldap: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rfc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub must: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secret: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub binary: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bytes: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DirectoryClassesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rfc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub oid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200DirectoryClassesItemRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Directory {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classes: Option<Vec<Answer200DirectoryClassesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MechanismsBackupCodes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Mechanisms {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<bool>,
        #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
        pub totp_usable: Option<bool>,
        #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
        pub mfa_required: Option<bool>,
        #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
        pub second_factor: Option<String>,
        #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
        pub backup_codes: Option<Answer200MechanismsBackupCodes>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LanguageOfferedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Language {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<Vec<Answer200LanguageOfferedItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CustomAttributesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub syntax: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub editable: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PhotoLimits {
        #[serde(rename = "maxFileBytes", default, skip_serializing_if = "Option::is_none")]
        pub max_file_bytes: Option<f64>,
        #[serde(rename = "maxStoredBytes", default, skip_serializing_if = "Option::is_none")]
        pub max_stored_bytes: Option<f64>,
        #[serde(rename = "minPixels", default, skip_serializing_if = "Option::is_none")]
        pub min_pixels: Option<f64>,
        #[serde(rename = "maxPixels", default, skip_serializing_if = "Option::is_none")]
        pub max_pixels: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub types: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Photo {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,
        #[serde(rename = "selfService", default, skip_serializing_if = "Option::is_none")]
        pub self_service: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<Answer200PhotoLimits>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<Answer200Entry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<Answer200Session>,
        #[serde(rename = "signOn", default, skip_serializing_if = "Option::is_none")]
        pub sign_on: Option<Answer200SignOn>,
        #[serde(rename = "sessionEnds", default, skip_serializing_if = "Option::is_none")]
        pub session_ends: Option<f64>,
        #[serde(rename = "timesSignedIn", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub times_signed_in: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<Answer200Directory>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mechanisms: Option<Answer200Mechanisms>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub language: Option<Answer200Language>,
        #[serde(rename = "customAttributes", default, skip_serializing_if = "Option::is_none")]
        pub custom_attributes: Option<Vec<Answer200CustomAttributesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub photo: Option<Answer200Photo>,
    }
}

/// What you own: applications
pub mod get_owned_applications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/owned/applications";
    pub const OPERATION_ID: &str = "getOwnedApplications";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemVia {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub you: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub detail: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<Answer200RowsItemVia>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub closed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// What you own: groups
pub mod get_owned_groups {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/owned/groups";
    pub const OPERATION_ID: &str = "getOwnedGroups";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemVia {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub you: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub detail: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<Answer200RowsItemVia>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub closed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// What you own: roles
pub mod get_owned_roles {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/owned/roles";
    pub const OPERATION_ID: &str = "getOwnedRoles";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemVia {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub you: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub detail: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<Answer200RowsItemVia>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub closed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// What you own: service accounts
pub mod get_owned_service_accounts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/owned/service-accounts";
    pub const OPERATION_ID: &str = "getOwnedServiceAccounts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemVia {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub you: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub detail: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub via: Option<Answer200RowsItemVia>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub closed: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// Whether you have a password, and what one must be
pub mod get_password {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/password";
    pub const OPERATION_ID: &str = "getPassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Rules {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "hasPassword", default, skip_serializing_if = "Option::is_none")]
        pub has_password: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Answer200Rules>,
    }
}

/// Changes your password
pub mod change_password {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/password";
    pub const OPERATION_ID: &str = "changePassword";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Your current password: a change re-proves it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<String>,
        /// The new password.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub next: Option<String>,
        /// The new password again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Sets your profile photo
pub mod set_profile_photo {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/photo";
    pub const OPERATION_ID: &str = "setProfilePhoto";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The JPEG or PNG file, base64-encoded.
        pub image: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub photo: Option<String>,
    }
}

/// Removes your profile photo
pub mod remove_profile_photo {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/photo/remove";
    pub const OPERATION_ID: &str = "removeProfilePhoto";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub photo: Option<String>,
    }
}

/// The other names you can sign in with
pub mod get_pseudonyms {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/pseudonyms";
    pub const OPERATION_ID: &str = "getPseudonyms";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pseudonyms: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pending: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cap: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
    }
}

/// Adds, removes or cancels one sign-in name
pub mod post_pseudonyms {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/pseudonyms";
    pub const OPERATION_ID: &str = "postPseudonyms";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "add")]
        Add,
        #[serde(rename = "remove")]
        Remove,
        #[serde(rename = "cancel-pending")]
        CancelPending,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `add` adds `value`; `remove` drops it; `cancel-pending` drops a name
        /// that is waiting for its link.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// The name, for `add` and `remove`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Checks a password reset link, and spends nothing
pub mod get_password_reset {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/reset-password";
    pub const OPERATION_ID: &str = "getPasswordReset";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Rules {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Answer200Rules>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<String>,
        #[serde(rename = "tooMany", default, skip_serializing_if = "Option::is_none")]
        pub too_many: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<bool>,
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
    }
}

/// Sets a new password from a reset link, and spends it
pub mod spend_password_reset {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/reset-password";
    pub const OPERATION_ID: &str = "spendPasswordReset";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The username the link names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// The link's single-use secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        /// The new password.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// The new password again.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewRules {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<Answer200ViewRules>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<String>,
        #[serde(rename = "tooMany", default, skip_serializing_if = "Option::is_none")]
        pub too_many: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<bool>,
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The wallet keys that sign you in with SIOPv2
pub mod get_self_issued {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/self-issued";
    pub const OPERATION_ID: &str = "getSelfIssued";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryDidV1 {
        #[serde(rename = "published")]
        Published,
        #[serde(rename = "authorized")]
        Authorized,
        #[serde(rename = "changed")]
        Changed,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum QueryDid {
        V1(QueryDidV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enrolled: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub did: Option<QueryDid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rid: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TurnOn {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub env: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub administrator: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub page: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Published {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custody: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(rename = "keyAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<i64>,
        #[serde(rename = "canPublish", default, skip_serializing_if = "Option::is_none")]
        pub can_publish: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dids: Option<Option<Vec<serde_json::Value>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectsItemLocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectsItem {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preferred: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<Answer200SubjectsItemLocation>,
        #[serde(rename = "didDocumentUrl", default, skip_serializing_if = "Option::is_none")]
        pub did_document_url: Option<String>,
        #[serde(rename = "didResolved", default, skip_serializing_if = "Option::is_none")]
        pub did_resolved: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FreshFile {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Fresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub did: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<Answer200FreshFile>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "turnOn", default, skip_serializing_if = "Option::is_none")]
        pub turn_on: Option<Answer200TurnOn>,
        #[serde(rename = "loginHint", default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
        #[serde(rename = "didClaim", default, skip_serializing_if = "Option::is_none")]
        pub did_claim: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub published: Option<Answer200Published>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subjects: Option<Vec<Answer200SubjectsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200Fresh>,
    }
}

/// Removes a self-issued subject of yours, or marks one as your preferred DID
pub mod remove_self_issued {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/self-issued";
    pub const OPERATION_ID: &str = "removeSelfIssued";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "remove")]
        Remove,
        #[serde(rename = "prefer")]
        Prefer,
        #[serde(rename = "unprefer")]
        Unprefer,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `remove` (the default) takes the subject off; `prefer` marks it as your
        /// preferred DID (#693), and `unprefer` clears the mark.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// The enrolled subject, from the list.
        pub subject: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTurnOn {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub env: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub administrator: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub page: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPublished {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custody: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(rename = "keyAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<i64>,
        #[serde(rename = "canPublish", default, skip_serializing_if = "Option::is_none")]
        pub can_publish: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dids: Option<Option<Vec<serde_json::Value>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSubjectsItemLocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSubjectsItem {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preferred: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<Answer200ViewSubjectsItemLocation>,
        #[serde(rename = "didDocumentUrl", default, skip_serializing_if = "Option::is_none")]
        pub did_document_url: Option<String>,
        #[serde(rename = "didResolved", default, skip_serializing_if = "Option::is_none")]
        pub did_resolved: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFreshFile {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub did: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<Answer200ViewFreshFile>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "turnOn", default, skip_serializing_if = "Option::is_none")]
        pub turn_on: Option<Answer200ViewTurnOn>,
        #[serde(rename = "loginHint", default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
        #[serde(rename = "didClaim", default, skip_serializing_if = "Option::is_none")]
        pub did_claim: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub published: Option<Answer200ViewPublished>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subjects: Option<Vec<Answer200ViewSubjectsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200ViewFresh>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The DID document of one of your enrolled did:jwk or did:key subjects
pub mod get_self_issued_did_document {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/self-issued/did";
    pub const OPERATION_ID: &str = "getSelfIssuedDidDocument";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        /// A DID document as the DID's method resolved it (W3C DID Core), or null:
        /// its verification methods and services are the DID controller's to state.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<serde_json::Value>,
    }
}

/// Publishes a did:web for you, changes its key, or deactivates it
pub mod act_on_published_did {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/self-issued/dids";
    pub const OPERATION_ID: &str = "actOnPublishedDid";

    /// `publish` a DID whose key this realm generates (`realm` or `download`
    /// custody); `add-key` or `rotate-key` of a `realm`-custody DID; `deactivate`
    /// one of your DIDs.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "publish")]
        Publish,
        #[serde(rename = "add-key")]
        AddKey,
        #[serde(rename = "rotate-key")]
        RotateKey,
        #[serde(rename = "deactivate")]
        Deactivate,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `publish` a DID whose key this realm generates (`realm` or `download`
        /// custody); `add-key` or `rotate-key` of a `realm`-custody DID;
        /// `deactivate` one of your DIDs.
        pub action: BodyAction,
        /// The published DID's random id, from the list; every action but `publish`
        /// names one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rid: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTurnOn {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub env: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub administrator: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub page: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPublished {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custody: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(rename = "keyAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<i64>,
        #[serde(rename = "canPublish", default, skip_serializing_if = "Option::is_none")]
        pub can_publish: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dids: Option<Option<Vec<serde_json::Value>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSubjectsItemLocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewSubjectsItem {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preferred: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub location: Option<Answer200ViewSubjectsItemLocation>,
        #[serde(rename = "didDocumentUrl", default, skip_serializing_if = "Option::is_none")]
        pub did_document_url: Option<String>,
        #[serde(rename = "didResolved", default, skip_serializing_if = "Option::is_none")]
        pub did_resolved: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFreshFile {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub did: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<Answer200ViewFreshFile>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "turnOn", default, skip_serializing_if = "Option::is_none")]
        pub turn_on: Option<Answer200ViewTurnOn>,
        #[serde(rename = "loginHint", default, skip_serializing_if = "Option::is_none")]
        pub login_hint: Option<String>,
        #[serde(rename = "didClaim", default, skip_serializing_if = "Option::is_none")]
        pub did_claim: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub published: Option<Answer200ViewPublished>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subjects: Option<Vec<Answer200ViewSubjectsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notice: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200ViewFresh>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// What you share through User-Managed Access
pub mod get_shared {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/shared";
    pub const OPERATION_ID: &str = "getShared";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ResourcesItemSharesItemRecipient {
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
    pub struct Answer200ResourcesItemSharesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
        pub resource_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recipient: Option<Answer200ResourcesItemSharesItemRecipient>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
        pub ask_me: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ResourcesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shares: Option<Vec<Answer200ResourcesItemSharesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CustomItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PendingItemPermissionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource_scopes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PendingItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(rename = "requestingParty", default, skip_serializing_if = "Option::is_none")]
        pub requesting_party: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<Answer200PendingItemPermissionsItem>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<Vec<Answer200ResourcesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custom: Option<Vec<Answer200CustomItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Vec<Answer200PendingItem>>,
        #[serde(rename = "alfaEditing", default, skip_serializing_if = "Option::is_none")]
        pub alfa_editing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub version: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recipients: Option<Vec<String>>,
    }
}

/// Shares a resource, removes a share, or rewrites your policy
pub mod act_shared {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/shared";
    pub const OPERATION_ID: &str = "actShared";

    /// share adds a share; unshare removes one; alfa replaces the whole document,
    /// where the realm allows it; approve and refuse answer a request waiting for
    /// you.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "share")]
        Share,
        #[serde(rename = "unshare")]
        Unshare,
        #[serde(rename = "alfa")]
        Alfa,
        #[serde(rename = "approve")]
        Approve,
        #[serde(rename = "refuse")]
        Refuse,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyScope {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRecipientKindV1 {
        #[serde(rename = "person")]
        Person,
        #[serde(rename = "group")]
        Group,
        #[serde(rename = "realm")]
        Realm,
        #[serde(rename = "claim")]
        Claim,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyRecipientKind {
        V1(BodyRecipientKindV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAskMeV1 {
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
    pub enum BodyAskMe {
        V1(BodyAskMeV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// share adds a share; unshare removes one; alfa replaces the whole
        /// document, where the realm allows it; approve and refuse answer a request
        /// waiting for you.
        pub action: BodyAction,
        /// approve, refuse: the waiting request's id, from the list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<String>,
        /// share: the resource's _id, one of yours.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        /// share: the scopes, each one the resource was registered with.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<BodyScope>,
        /// share: who the share is with.
        #[serde(rename = "recipientKind", default, skip_serializing_if = "Option::is_none")]
        pub recipient_kind: Option<BodyRecipientKind>,
        /// share: the username, the group's name, or the claim's value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recipient: Option<String>,
        /// share, recipientKind claim: the claim's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        /// share: an optional date the share ends.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<String>,
        /// share: an optional authentication level the requesting party's session
        /// must meet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        /// share: ask the owner each time.
        #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
        pub ask_me: Option<BodyAskMe>,
        /// unshare: the share's id, from the list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub share: Option<String>,
        /// alfa: the whole document, as ALFA.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
        /// The page of the list the form was on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewResourcesItemSharesItemRecipient {
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
    pub struct Answer200ViewResourcesItemSharesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
        pub resource_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recipient: Option<Answer200ViewResourcesItemSharesItemRecipient>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
        pub ask_me: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewResourcesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shares: Option<Vec<Answer200ViewResourcesItemSharesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewCustomItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPendingItemPermissionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource_scopes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPendingItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(rename = "requestingParty", default, skip_serializing_if = "Option::is_none")]
        pub requesting_party: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<Answer200ViewPendingItemPermissionsItem>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<Vec<Answer200ViewResourcesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200ViewPaging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custom: Option<Vec<Answer200ViewCustomItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Vec<Answer200ViewPendingItem>>,
        #[serde(rename = "alfaEditing", default, skip_serializing_if = "Option::is_none")]
        pub alfa_editing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub version: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recipients: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// What others share with you
pub mod get_shared_with_me {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/shared-with-me";
    pub const OPERATION_ID: &str = "getSharedWithMe";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
        pub resource_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// Your assessed sign-ins, with the application of each
pub mod get_sign_ins {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/sign-ins";
    pub const OPERATION_ID: &str = "getSignIns";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub city: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub country: Option<String>,
        #[serde(rename = "asOrg", default, skip_serializing_if = "Option::is_none")]
        pub as_org: Option<String>,
        #[serde(rename = "addressPrefix", default, skip_serializing_if = "Option::is_none")]
        pub address_prefix: Option<String>,
        #[serde(rename = "uaFamily", default, skip_serializing_if = "Option::is_none")]
        pub ua_family: Option<String>,
        #[serde(rename = "uaOs", default, skip_serializing_if = "Option::is_none")]
        pub ua_os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub feedback: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<f64>,
        #[serde(rename = "thisSession", default, skip_serializing_if = "Option::is_none")]
        pub this_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
    }
}

/// Says whether a sign-in was you
pub mod answer_sign_in {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/sign-ins";
    pub const OPERATION_ID: &str = "answerSignIn";

    /// `confirm`: this was me. `deny`: this was not me.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAction {
        #[serde(rename = "confirm")]
        Confirm,
        #[serde(rename = "deny")]
        Deny,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `confirm`: this was me. `deny`: this was not me.
        pub action: BodyAction,
        /// The assessment's id, from the list.
        pub assessment: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub city: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub country: Option<String>,
        #[serde(rename = "asOrg", default, skip_serializing_if = "Option::is_none")]
        pub as_org: Option<String>,
        #[serde(rename = "addressPrefix", default, skip_serializing_if = "Option::is_none")]
        pub address_prefix: Option<String>,
        #[serde(rename = "uaFamily", default, skip_serializing_if = "Option::is_none")]
        pub ua_family: Option<String>,
        #[serde(rename = "uaOs", default, skip_serializing_if = "Option::is_none")]
        pub ua_os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub door: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub feedback: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<f64>,
        #[serde(rename = "thisSession", default, skip_serializing_if = "Option::is_none")]
        pub this_session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200ViewPaging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200ViewRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ended: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// The security events this portal was told about you
pub mod get_security_activity {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/signals";
    pub const OPERATION_ID: &str = "getSecurityActivity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub done: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemReactionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skipped: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub observed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ended: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vocabulary: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        /// The event's payload as a transmitter signed it: CAEP and RISC events
        /// carry members by event type, and an unknown type is shown as it came.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(rename = "verificationNote", default, skip_serializing_if = "Option::is_none")]
        pub verification_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reactions: Option<Vec<Answer200RowsItemReactionsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Participation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applies: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hours: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub moves: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub incomplete: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub participation: Option<Answer200Participation>,
    }
}

/// Stops, cancels stopping, or resumes sharing security events about you
pub mod move_risc_participation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/signals";
    pub const OPERATION_ID: &str = "moveRiscParticipation";

    /// The move: start opting out, cancel that, or opt back in.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyMove {
        #[serde(rename = "optOutInitiated")]
        OptOutInitiated,
        #[serde(rename = "optOutCancelled")]
        OptOutCancelled,
        #[serde(rename = "optIn")]
        OptIn,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The move: start opting out, cancel that, or opt back in.
        #[serde(rename = "move", default, skip_serializing_if = "Option::is_none")]
        pub move_: Option<BodyMove>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
    }
}

/// Your signing key pairs and TLS client certificates
pub mod get_signing_keys {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/signing-key";
    pub const OPERATION_ID: &str = "getSigningKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItemHeldKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
        pub revoked_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItemHeld {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200ProfilesItemHeldKeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuers: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rfc: Option<String>,
        #[serde(rename = "grantType", default, skip_serializing_if = "Option::is_none")]
        pub grant_type: Option<String>,
        #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
        pub at_cap: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<Answer200ProfilesItemHeld>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TlsHeldItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
        pub revoked_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Tls {
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trusted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(rename = "keyAlgs", default, skip_serializing_if = "Option::is_none")]
        pub key_algs: Option<Vec<String>>,
        #[serde(rename = "defaultKeyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default_key_alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<Vec<Answer200TlsHeldItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FreshIssued {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FreshFilesKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FreshFilesChain {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FreshFiles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<Answer200FreshFilesKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<Answer200FreshFilesChain>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Fresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Answer200FreshIssued>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub files: Option<Answer200FreshFiles>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(rename = "jwsAlg", default, skip_serializing_if = "Option::is_none")]
        pub jws_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<bool>,
        #[serde(rename = "holdsAny", default, skip_serializing_if = "Option::is_none")]
        pub holds_any: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuable: Option<bool>,
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ProfilesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls: Option<Answer200Tls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200Fresh>,
    }
}

/// Generates or revokes a signing key or TLS certificate
pub mod change_signing_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/signing-key";
    pub const OPERATION_ID: &str = "changeSigningKeys";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyActionV1 {
        #[serde(rename = "generate")]
        Generate,
        #[serde(rename = "revoke")]
        Revoke,
        #[serde(rename = "generate-tls-client")]
        GenerateTlsClient,
        #[serde(rename = "revoke-tls-client")]
        RevokeTlsClient,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyAction {
        V1(BodyActionV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlgV1 {
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
    #[serde(untagged)]
    pub enum BodyKeyAlg {
        V1(BodyKeyAlgV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReasonV1 {
        #[serde(rename = "cessationOfOperation")]
        CessationOfOperation,
        #[serde(rename = "keyCompromise")]
        KeyCompromise,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyReason {
        V1(BodyReasonV1),
        String(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPurposeV1 {
        #[serde(rename = "jwt")]
        Jwt,
        #[serde(rename = "saml")]
        Saml,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyPurpose {
        V1(BodyPurposeV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `generate` a signing key pair (for `purpose`) or `revoke` one of yours
        /// (by `handle`); `generate-tls-client` or `revoke-tls-client` a TLS client
        /// certificate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<BodyAction>,
        /// For `generate`: what you call the key pair. For `generate-tls-client`:
        /// what you call the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// For `revoke`: the key pair's `kid` (RFC 7523) or certificate thumbprint
        /// (RFC 7522), one of yours.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        /// For `generate-tls-client`: the key algorithm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        /// For `revoke-tls-client`: the certificate's serial, one of yours.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub serial: Option<String>,
        /// For `revoke` and `revoke-tls-client`: why.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
        /// For `generate` and `revoke`: RFC 7523's `jwt` key pairs (the default) or
        /// RFC 7522's `saml` ones.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<BodyPurpose>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StepUp {
        #[serde(rename = "acrValues", default, skip_serializing_if = "Option::is_none")]
        pub acr_values: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prompt: Option<String>,
        #[serde(rename = "maxAge", default, skip_serializing_if = "Option::is_none")]
        pub max_age: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewProfilesItemHeldKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
        pub revoked_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewProfilesItemHeld {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200ViewProfilesItemHeldKeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuers: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rfc: Option<String>,
        #[serde(rename = "grantType", default, skip_serializing_if = "Option::is_none")]
        pub grant_type: Option<String>,
        #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
        pub at_cap: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<Answer200ViewProfilesItemHeld>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTlsHeldItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
        pub revoked_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewTls {
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trusted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(rename = "keyAlgs", default, skip_serializing_if = "Option::is_none")]
        pub key_algs: Option<Vec<String>>,
        #[serde(rename = "defaultKeyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default_key_alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<Vec<Answer200ViewTlsHeldItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFreshIssued {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFreshFilesKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFreshFilesChain {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mime: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub base64: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFreshFiles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<Answer200ViewFreshFilesKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<Answer200ViewFreshFilesChain>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ViewFresh {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Answer200ViewFreshIssued>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub files: Option<Answer200ViewFreshFiles>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(rename = "jwsAlg", default, skip_serializing_if = "Option::is_none")]
        pub jws_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<bool>,
        #[serde(rename = "holdsAny", default, skip_serializing_if = "Option::is_none")]
        pub holds_any: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuable: Option<bool>,
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
        pub max_per_person: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ViewProfilesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls: Option<Answer200ViewTls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fresh: Option<Answer200ViewFresh>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "stepUp", default, skip_serializing_if = "Option::is_none")]
        pub step_up: Option<Answer200StepUp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Checks an address verification link, and spends nothing
pub mod get_email_verification {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/verify-email";
    pub const OPERATION_ID: &str = "getEmailVerification";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
    }
}

/// Verifies the address an address verification link names
pub mod verify_email {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/verify-email";
    pub const OPERATION_ID: &str = "verifyEmail";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The username the link names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// The link's single-use secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Checks a sign-in-name link, and spends nothing
pub mod get_pseudonym_verification {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/account-api/verify-pseudonym";
    pub const OPERATION_ID: &str = "getPseudonymVerification";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
    }
}

/// Confirms the sign-in name a link names
pub mod verify_pseudonym {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/account-api/verify-pseudonym";
    pub const OPERATION_ID: &str = "verifyPseudonym";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The username the link names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// The link's single-use secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200View {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub go: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200View>,
    }
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "decideAccessRequest" => Some(serde_json::from_value::<decide_access_request::Body>(value.clone()).map(|_| ())),
        "activate" => Some(serde_json::from_value::<activate::Body>(value.clone()).map(|_| ())),
        "changeAppPasswords" => Some(serde_json::from_value::<change_app_passwords::Body>(value.clone()).map(|_| ())),
        "setCustomAttribute" => Some(serde_json::from_value::<set_custom_attribute::Body>(value.clone()).map(|_| ())),
        "changeCertificates" => Some(serde_json::from_value::<change_certificates::Body>(value.clone()).map(|_| ())),
        "answerSignInRequest" => Some(serde_json::from_value::<answer_sign_in_request::Body>(value.clone()).map(|_| ())),
        "linkClaimSource" => Some(serde_json::from_value::<link_claim_source::Body>(value.clone()).map(|_| ())),
        "connectAccount" => Some(serde_json::from_value::<connect_account::Body>(value.clone()).map(|_| ())),
        "withdrawConsent" => Some(serde_json::from_value::<withdraw_consent::Body>(value.clone()).map(|_| ())),
        "createCredentialOffer" => Some(serde_json::from_value::<create_credential_offer::Body>(value.clone()).map(|_| ())),
        "removeIssuedCredential" => Some(serde_json::from_value::<remove_issued_credential::Body>(value.clone()).map(|_| ())),
        "setDelegate" => Some(serde_json::from_value::<set_delegate::Body>(value.clone()).map(|_| ())),
        "answerDeviceRequest" => Some(serde_json::from_value::<answer_device_request::Body>(value.clone()).map(|_| ())),
        "actOnDevices" => Some(serde_json::from_value::<act_on_devices::Body>(value.clone()).map(|_| ())),
        "deviceChallenge" => Some(serde_json::from_value::<device_challenge::Body>(value.clone()).map(|_| ())),
        "deviceProof" => Some(serde_json::from_value::<device_proof::Body>(value.clone()).map(|_| ())),
        "postEmail" => Some(serde_json::from_value::<post_email::Body>(value.clone()).map(|_| ())),
        "requestPasswordReset" => Some(serde_json::from_value::<request_password_reset::Body>(value.clone()).map(|_| ())),
        "revokeGnapGrant" => Some(serde_json::from_value::<revoke_gnap_grant::Body>(value.clone()).map(|_| ())),
        "makeKeytab" => Some(serde_json::from_value::<make_keytab::Body>(value.clone()).map(|_| ())),
        "enrolKey" => Some(serde_json::from_value::<enrol_key::Body>(value.clone()).map(|_| ())),
        "removeKey" => Some(serde_json::from_value::<remove_key::Body>(value.clone()).map(|_| ())),
        "renameKey" => Some(serde_json::from_value::<rename_key::Body>(value.clone()).map(|_| ())),
        "setLanguage" => Some(serde_json::from_value::<set_language::Body>(value.clone()).map(|_| ())),
        "changeMfa" => Some(serde_json::from_value::<change_mfa::Body>(value.clone()).map(|_| ())),
        "changePassword" => Some(serde_json::from_value::<change_password::Body>(value.clone()).map(|_| ())),
        "setProfilePhoto" => Some(serde_json::from_value::<set_profile_photo::Body>(value.clone()).map(|_| ())),
        "postPseudonyms" => Some(serde_json::from_value::<post_pseudonyms::Body>(value.clone()).map(|_| ())),
        "spendPasswordReset" => Some(serde_json::from_value::<spend_password_reset::Body>(value.clone()).map(|_| ())),
        "removeSelfIssued" => Some(serde_json::from_value::<remove_self_issued::Body>(value.clone()).map(|_| ())),
        "actOnPublishedDid" => Some(serde_json::from_value::<act_on_published_did::Body>(value.clone()).map(|_| ())),
        "actShared" => Some(serde_json::from_value::<act_shared::Body>(value.clone()).map(|_| ())),
        "answerSignIn" => Some(serde_json::from_value::<answer_sign_in::Body>(value.clone()).map(|_| ())),
        "moveRiscParticipation" => Some(serde_json::from_value::<move_risc_participation::Body>(value.clone()).map(|_| ())),
        "changeSigningKeys" => Some(serde_json::from_value::<change_signing_keys::Body>(value.clone()).map(|_| ())),
        "verifyEmail" => Some(serde_json::from_value::<verify_email::Body>(value.clone()).map(|_| ())),
        "verifyPseudonym" => Some(serde_json::from_value::<verify_pseudonym::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getIndex", 200) => Some(serde_json::from_value::<get_index::Answer200>(value.clone()).map(|_| ())),
        ("getAccessRequests", 200) => Some(serde_json::from_value::<get_access_requests::Answer200>(value.clone()).map(|_| ())),
        ("decideAccessRequest", 200) => Some(serde_json::from_value::<decide_access_request::Answer200>(value.clone()).map(|_| ())),
        ("getActivation", 200) => Some(serde_json::from_value::<get_activation::Answer200>(value.clone()).map(|_| ())),
        ("activate", 200) => Some(serde_json::from_value::<activate::Answer200>(value.clone()).map(|_| ())),
        ("getAnnouncements", 200) => Some(serde_json::from_value::<get_announcements::Answer200>(value.clone()).map(|_| ())),
        ("getAppPasswords", 200) => Some(serde_json::from_value::<get_app_passwords::Answer200>(value.clone()).map(|_| ())),
        ("changeAppPasswords", 200) => Some(serde_json::from_value::<change_app_passwords::Answer200>(value.clone()).map(|_| ())),
        ("getApplications", 200) => Some(serde_json::from_value::<get_applications::Answer200>(value.clone()).map(|_| ())),
        ("setCustomAttribute", 200) => Some(serde_json::from_value::<set_custom_attribute::Answer200>(value.clone()).map(|_| ())),
        ("getCertificates", 200) => Some(serde_json::from_value::<get_certificates::Answer200>(value.clone()).map(|_| ())),
        ("changeCertificates", 200) => Some(serde_json::from_value::<change_certificates::Answer200>(value.clone()).map(|_| ())),
        ("getSignInRequests", 200) => Some(serde_json::from_value::<get_sign_in_requests::Answer200>(value.clone()).map(|_| ())),
        ("answerSignInRequest", 200) => Some(serde_json::from_value::<answer_sign_in_request::Answer200>(value.clone()).map(|_| ())),
        ("getClaimSources", 200) => Some(serde_json::from_value::<get_claim_sources::Answer200>(value.clone()).map(|_| ())),
        ("linkClaimSource", 200) => Some(serde_json::from_value::<link_claim_source::Answer200>(value.clone()).map(|_| ())),
        ("getConnectedAccounts", 200) => Some(serde_json::from_value::<get_connected_accounts::Answer200>(value.clone()).map(|_| ())),
        ("connectAccount", 200) => Some(serde_json::from_value::<connect_account::Answer200>(value.clone()).map(|_| ())),
        ("getConsents", 200) => Some(serde_json::from_value::<get_consents::Answer200>(value.clone()).map(|_| ())),
        ("withdrawConsent", 200) => Some(serde_json::from_value::<withdraw_consent::Answer200>(value.clone()).map(|_| ())),
        ("getOfferableCredentials", 200) => Some(serde_json::from_value::<get_offerable_credentials::Answer200>(value.clone()).map(|_| ())),
        ("createCredentialOffer", 200) => Some(serde_json::from_value::<create_credential_offer::Answer200>(value.clone()).map(|_| ())),
        ("removeIssuedCredential", 200) => Some(serde_json::from_value::<remove_issued_credential::Answer200>(value.clone()).map(|_| ())),
        ("getDelegate", 200) => Some(serde_json::from_value::<get_delegate::Answer200>(value.clone()).map(|_| ())),
        ("setDelegate", 200) => Some(serde_json::from_value::<set_delegate::Answer200>(value.clone()).map(|_| ())),
        ("findDelegateCandidates", 200) => Some(serde_json::from_value::<find_delegate_candidates::Answer200>(value.clone()).map(|_| ())),
        ("getDeviceRequest", 200) => Some(serde_json::from_value::<get_device_request::Answer200>(value.clone()).map(|_| ())),
        ("answerDeviceRequest", 200) => Some(serde_json::from_value::<answer_device_request::Answer200>(value.clone()).map(|_| ())),
        ("getDevices", 200) => Some(serde_json::from_value::<get_devices::Answer200>(value.clone()).map(|_| ())),
        ("actOnDevices", 200) => Some(serde_json::from_value::<act_on_devices::Answer200>(value.clone()).map(|_| ())),
        ("deviceChallenge", 200) => Some(serde_json::from_value::<device_challenge::Answer200>(value.clone()).map(|_| ())),
        ("deviceProof", 200) => Some(serde_json::from_value::<device_proof::Answer200>(value.clone()).map(|_| ())),
        ("deviceProof", 201) => Some(serde_json::from_value::<device_proof::Answer201>(value.clone()).map(|_| ())),
        ("getEmail", 200) => Some(serde_json::from_value::<get_email::Answer200>(value.clone()).map(|_| ())),
        ("postEmail", 200) => Some(serde_json::from_value::<post_email::Answer200>(value.clone()).map(|_| ())),
        ("getForgotPassword", 200) => Some(serde_json::from_value::<get_forgot_password::Answer200>(value.clone()).map(|_| ())),
        ("requestPasswordReset", 200) => Some(serde_json::from_value::<request_password_reset::Answer200>(value.clone()).map(|_| ())),
        ("getGnapGrants", 200) => Some(serde_json::from_value::<get_gnap_grants::Answer200>(value.clone()).map(|_| ())),
        ("revokeGnapGrant", 200) => Some(serde_json::from_value::<revoke_gnap_grant::Answer200>(value.clone()).map(|_| ())),
        ("getKerberos", 200) => Some(serde_json::from_value::<get_kerberos::Answer200>(value.clone()).map(|_| ())),
        ("makeKeytab", 200) => Some(serde_json::from_value::<make_keytab::Answer200>(value.clone()).map(|_| ())),
        ("getKeys", 200) => Some(serde_json::from_value::<get_keys::Answer200>(value.clone()).map(|_| ())),
        ("enrolKey", 200) => Some(serde_json::from_value::<enrol_key::Answer200>(value.clone()).map(|_| ())),
        ("removeKey", 200) => Some(serde_json::from_value::<remove_key::Answer200>(value.clone()).map(|_| ())),
        ("renameKey", 200) => Some(serde_json::from_value::<rename_key::Answer200>(value.clone()).map(|_| ())),
        ("setLanguage", 200) => Some(serde_json::from_value::<set_language::Answer200>(value.clone()).map(|_| ())),
        ("getLocale", 200) => Some(serde_json::from_value::<get_locale::Answer200>(value.clone()).map(|_| ())),
        ("getMe", 200) => Some(serde_json::from_value::<get_me::Answer200>(value.clone()).map(|_| ())),
        ("getMfa", 200) => Some(serde_json::from_value::<get_mfa::Answer200>(value.clone()).map(|_| ())),
        ("changeMfa", 200) => Some(serde_json::from_value::<change_mfa::Answer200>(value.clone()).map(|_| ())),
        ("getOpenApi", 200) => Some(serde_json::from_value::<get_open_api::Answer200>(value.clone()).map(|_| ())),
        ("getOverview", 200) => Some(serde_json::from_value::<get_overview::Answer200>(value.clone()).map(|_| ())),
        ("getOwnedApplications", 200) => Some(serde_json::from_value::<get_owned_applications::Answer200>(value.clone()).map(|_| ())),
        ("getOwnedGroups", 200) => Some(serde_json::from_value::<get_owned_groups::Answer200>(value.clone()).map(|_| ())),
        ("getOwnedRoles", 200) => Some(serde_json::from_value::<get_owned_roles::Answer200>(value.clone()).map(|_| ())),
        ("getOwnedServiceAccounts", 200) => Some(serde_json::from_value::<get_owned_service_accounts::Answer200>(value.clone()).map(|_| ())),
        ("getPassword", 200) => Some(serde_json::from_value::<get_password::Answer200>(value.clone()).map(|_| ())),
        ("changePassword", 200) => Some(serde_json::from_value::<change_password::Answer200>(value.clone()).map(|_| ())),
        ("setProfilePhoto", 200) => Some(serde_json::from_value::<set_profile_photo::Answer200>(value.clone()).map(|_| ())),
        ("removeProfilePhoto", 200) => Some(serde_json::from_value::<remove_profile_photo::Answer200>(value.clone()).map(|_| ())),
        ("getPseudonyms", 200) => Some(serde_json::from_value::<get_pseudonyms::Answer200>(value.clone()).map(|_| ())),
        ("postPseudonyms", 200) => Some(serde_json::from_value::<post_pseudonyms::Answer200>(value.clone()).map(|_| ())),
        ("getPasswordReset", 200) => Some(serde_json::from_value::<get_password_reset::Answer200>(value.clone()).map(|_| ())),
        ("spendPasswordReset", 200) => Some(serde_json::from_value::<spend_password_reset::Answer200>(value.clone()).map(|_| ())),
        ("getSelfIssued", 200) => Some(serde_json::from_value::<get_self_issued::Answer200>(value.clone()).map(|_| ())),
        ("removeSelfIssued", 200) => Some(serde_json::from_value::<remove_self_issued::Answer200>(value.clone()).map(|_| ())),
        ("getSelfIssuedDidDocument", 200) => Some(serde_json::from_value::<get_self_issued_did_document::Answer200>(value.clone()).map(|_| ())),
        ("actOnPublishedDid", 200) => Some(serde_json::from_value::<act_on_published_did::Answer200>(value.clone()).map(|_| ())),
        ("getShared", 200) => Some(serde_json::from_value::<get_shared::Answer200>(value.clone()).map(|_| ())),
        ("actShared", 200) => Some(serde_json::from_value::<act_shared::Answer200>(value.clone()).map(|_| ())),
        ("getSharedWithMe", 200) => Some(serde_json::from_value::<get_shared_with_me::Answer200>(value.clone()).map(|_| ())),
        ("getSignIns", 200) => Some(serde_json::from_value::<get_sign_ins::Answer200>(value.clone()).map(|_| ())),
        ("answerSignIn", 200) => Some(serde_json::from_value::<answer_sign_in::Answer200>(value.clone()).map(|_| ())),
        ("getSecurityActivity", 200) => Some(serde_json::from_value::<get_security_activity::Answer200>(value.clone()).map(|_| ())),
        ("moveRiscParticipation", 200) => Some(serde_json::from_value::<move_risc_participation::Answer200>(value.clone()).map(|_| ())),
        ("getSigningKeys", 200) => Some(serde_json::from_value::<get_signing_keys::Answer200>(value.clone()).map(|_| ())),
        ("changeSigningKeys", 200) => Some(serde_json::from_value::<change_signing_keys::Answer200>(value.clone()).map(|_| ())),
        ("getEmailVerification", 200) => Some(serde_json::from_value::<get_email_verification::Answer200>(value.clone()).map(|_| ())),
        ("verifyEmail", 200) => Some(serde_json::from_value::<verify_email::Answer200>(value.clone()).map(|_| ())),
        ("getPseudonymVerification", 200) => Some(serde_json::from_value::<get_pseudonym_verification::Answer200>(value.clone()).map(|_| ())),
        ("verifyPseudonym", 200) => Some(serde_json::from_value::<verify_pseudonym::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
