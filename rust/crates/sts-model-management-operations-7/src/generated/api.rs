// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// Announcements the console's receiver took in
pub mod get_console_announcements {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/announcements";
    pub const OPERATION_ID: &str = "getConsoleAnnouncements";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
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

/// What an announcement can reach from this realm
pub mod get_broadcast {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/broadcast";
    pub const OPERATION_ID: &str = "getBroadcast";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SurfacesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub surfaces: Option<Vec<Answer200SurfacesItem>>,
        #[serde(rename = "everyRealm", default, skip_serializing_if = "Option::is_none")]
        pub every_realm: Option<bool>,
        #[serde(rename = "realmCount", default, skip_serializing_if = "Option::is_none")]
        pub realm_count: Option<i64>,
        #[serde(rename = "maxChars", default, skip_serializing_if = "Option::is_none")]
        pub max_chars: Option<f64>,
        #[serde(rename = "pollMs", default, skip_serializing_if = "Option::is_none")]
        pub poll_ms: Option<f64>,
        #[serde(rename = "keepS", default, skip_serializing_if = "Option::is_none")]
        pub keep_s: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ready: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }
}

/// Show an announcement to everybody signed in
pub mod send_broadcast {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/broadcast/send";
    pub const OPERATION_ID: &str = "sendBroadcast";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySurfacesItem {
        #[serde(rename = "admin-console")]
        AdminConsole,
        #[serde(rename = "user-portal")]
        UserPortal,
        #[serde(rename = "report")]
        Report,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Plain text, at most ssf.announcementMaxChars characters.
        pub message: String,
        /// Which applications show it.
        pub surfaces: Vec<BodySurfacesItem>,
        /// Every realm, not only this one.
        #[serde(rename = "everyRealm", default, skip_serializing_if = "Option::is_none")]
        pub every_realm: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors5;
}

/// Everything this service is still holding for one identity, across every
/// protocol family
pub mod get_live_sessions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/logout";
    pub const OPERATION_ID: &str = "getLiveSessions";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryDeliveryState {
        #[serde(rename = "pending")]
        Pending,
        #[serde(rename = "sent")]
        Sent,
        #[serde(rename = "dead")]
        Dead,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(rename = "deliveryState", default, skip_serializing_if = "Option::is_none")]
        pub delivery_state: Option<QueryDeliveryState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliveryq: Option<String>,
        #[serde(rename = "backchannelDeliveriesPage", default, skip_serializing_if = "Option::is_none")]
        pub backchannel_deliveries_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FamiliesItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
        pub started_at: Option<f64>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FamiliesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200FamiliesItemRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<f64>,
        #[serde(rename = "notListed", default, skip_serializing_if = "Option::is_none")]
        pub not_listed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failure: Option<String>,
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
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "familyLabel", default, skip_serializing_if = "Option::is_none")]
        pub family_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
        pub started_at: Option<f64>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200BackchannelDeliveriesItem {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<bool>,
        #[serde(rename = "canWrite", default, skip_serializing_if = "Option::is_none")]
        pub can_write: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessions: Option<f64>,
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
        pub families: Option<Vec<Answer200FamiliesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(rename = "backchannelDeliveries", default, skip_serializing_if = "Option::is_none")]
        pub backchannel_deliveries: Option<Vec<Answer200BackchannelDeliveriesItem>>,
        #[serde(rename = "backchannelDeliveriesPaging", default, skip_serializing_if = "Option::is_none")]
        pub backchannel_deliveries_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "backchannelCounts", default, skip_serializing_if = "Option::is_none")]
        pub backchannel_counts: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "deliveryState", default, skip_serializing_if = "Option::is_none")]
        pub delivery_state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliveryq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue>,
        #[serde(rename = "hasReader", default, skip_serializing_if = "Option::is_none")]
        pub has_reader: Option<bool>,
        #[serde(rename = "kerberosRealm", default, skip_serializing_if = "Option::is_none")]
        pub kerberos_realm: Option<String>,
        #[serde(rename = "opensTestControls", default, skip_serializing_if = "Option::is_none")]
        pub opens_test_controls: Option<bool>,
    }
}

/// End named items and nothing else
pub mod end_live_sessions {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/logout/end";
    pub const OPERATION_ID: &str = "endLiveSessions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identity to act on.
        pub user: String,
        /// Row ids from `GET /admin-api/logout?user=`.
        pub select: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors54;
}

/// End everything this service holds for one identity
pub mod global_logout {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/logout/global";
    pub const OPERATION_ID: &str = "globalLogout";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identity to sign out, as typed. Normalised the way the GET
        /// normalises one.
        pub user: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors54;
}

/// NON-SPEC: clear the Kerberos sign-out instant
pub mod clear_kerberos_sign_out {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/logout/restore-kerberos";
    pub const OPERATION_ID: &str = "clearKerberosSignOut";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identity whose principal to clear.
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

/// NON-SPEC: un-revoke a token a logout revoked
pub mod restore_logged_out_token {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/logout/restore-token";
    pub const OPERATION_ID: &str = "restoreLoggedOutToken";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identity, for the audit row.
        pub user: String,
        /// The token to restore.
        pub jti: String,
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
        pub jti: Option<String>,
    }
}

/// Send a dead back-channel Logout Token delivery again
pub mod retry_backchannel_delivery {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/logout/retry-backchannel";
    pub const OPERATION_ID: &str = "retryBackchannelDelivery";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The delivery's `id`, from `backchannelDeliveries`.
        pub delivery: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors55;
}

/// Every trust realm, its endpoints and what it sets
pub mod get_realms {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/realms";
    pub const OPERATION_ID: &str = "getRealms";

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
    pub struct Answer200RealmsItemRetiring {
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
    pub struct Answer200RealmsItemListenersItemHereCertificate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmsItemListenersItemHere {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        #[serde(rename = "publicBaseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub public_base_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hostnames: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
        #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Answer200RealmsItemListenersItemHereCertificate>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmsItemListenersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        #[serde(rename = "publicBaseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub public_base_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hostnames: Option<Vec<String>>,
        #[serde(rename = "clientAuth", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_auth: Option<Option<String>>,
        #[serde(rename = "certificateSource", default, skip_serializing_if = "Option::is_none")]
        pub certificate_source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub here: Option<Answer200RealmsItemListenersItemHere>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmsItemSettingsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmsItemEndpoints {
        #[serde(rename = "openidConfiguration", default, skip_serializing_if = "Option::is_none")]
        pub openid_configuration: Option<String>,
        #[serde(rename = "authorizationServerMetadata", default, skip_serializing_if = "Option::is_none")]
        pub authorization_server_metadata: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwks: Option<String>,
        #[serde(rename = "samlMetadata", default, skip_serializing_if = "Option::is_none")]
        pub saml_metadata: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RealmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub description: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub domain: Option<String>,
        #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
        pub base_dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub builtin: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retiring: Option<Answer200RealmsItemRetiring>,
        #[serde(rename = "pathPrefix", default, skip_serializing_if = "Option::is_none")]
        pub path_prefix: Option<String>,
        #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
        pub base_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listeners: Option<Vec<Answer200RealmsItemListenersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kid: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Vec<Answer200RealmsItemSettingsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Answer200RealmsItemEndpoints>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SupportItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cards: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Persistence {
        #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
        pub persists_realms: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(rename = "pathSegment", default, skip_serializing_if = "Option::is_none")]
        pub path_segment: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reserved: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realms: Option<Vec<Answer200RealmsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub support: Option<Vec<Answer200SupportItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
        #[serde(rename = "defaultDomain", default, skip_serializing_if = "Option::is_none")]
        pub default_domain: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
        #[serde(rename = "currentName", default, skip_serializing_if = "Option::is_none")]
        pub current_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persistence: Option<Answer200Persistence>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_2::PagingValue>,
    }
}

/// Define a trust realm
pub mod create_realm {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/realms/create";
    pub const OPERATION_ID: &str = "createRealm";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Lower-case letters, digits and hyphens. It is the path segment.
        pub id: String,
        /// What a person calls it. Free text; defaults to the id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// The realm's DNS domain, at least two labels. Fixed once the realm
        /// exists; defaults to `<id>.<global.domain>`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub domain: Option<String>,
        /// Settings to set on the realm, named by the dot paths GET
        /// /admin-api/config lists. They win over the seeded names. Every
        /// `realms.*` key is refused on a realm: one of them decides whether realms
        /// exist and where they are found, and a realm carrying it would be
        /// changing how it was reached half way through the request that found it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub overrides: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors66;
}

/// Remove a realm, and everything it holds
pub mod remove_realm {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/realms/remove";
    pub const OPERATION_ID: &str = "removeRealm";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors66;
}

/// Set one setting on one realm
pub mod set_realm_setting {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/realms/set";
    pub const OPERATION_ID: &str = "setRealmSetting";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub id: String,
        pub key: String,
        pub value: serde_json::Value,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors66;
}

/// Drop one setting from one realm
pub mod unset_realm_setting {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/realms/unset";
    pub const OPERATION_ID: &str = "unsetRealmSetting";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub id: String,
        pub key: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors66;
}

/// Rename a realm, or describe it
pub mod update_realm {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/realms/update";
    pub const OPERATION_ID: &str = "updateRealm";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub domain: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors66;
}

/// Every session this service is holding right now, across the three protocols
/// that have one
pub mod get_sessions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/sessions";
    pub const OPERATION_ID: &str = "getSessions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<String>,
        #[serde(rename = "anonymousPage", default, skip_serializing_if = "Option::is_none")]
        pub anonymous_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::SessionList;
}

/// End every sign-on session in this realm
pub mod end_all_sessions {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/sessions/end-all";
    pub const OPERATION_ID: &str = "endAllSessions";

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
        pub message: String,
    }
}

/// End one live session
pub mod revoke_session {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/sessions/revoke";
    pub const OPERATION_ID: &str = "revokeSession";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Whose session it is: the normalised identity key, which every row of GET
        /// /admin-api/sessions carries as `key`. The termination is keyed on an
        /// identity, which is why this is needed beside the id.
        pub key: String,
        /// Which session, in the form the list gives it as `id`: `session:…`,
        /// `ldap:…` or `krb5:…@REALM`. It is the identifier POST
        /// /admin-api/logout/selective takes too, because both go through one
        /// termination.
        pub select: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors54;
}

/// Every security event delivered TO this console
pub mod get_signals {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/signals";
    pub const OPERATION_ID: &str = "getSignals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sigq: Option<String>,
        #[serde(rename = "receivedPage", default, skip_serializing_if = "Option::is_none")]
        pub received_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::Signals;
}

/// Empty the console's Shared Signals inbox
pub mod clear_signals_inbox {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/signals/clear";
    pub const OPERATION_ID: &str = "clearSignalsInbox";

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

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dropped: Option<i64>,
    }
}

/// The Shared Signals transmitter: its streams, their subjects, their queues
/// and what a receiver refused
pub mod get_ssf {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ssf";
    pub const OPERATION_ID: &str = "getSsf";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stream: Option<String>,
        #[serde(rename = "streamsPage", default, skip_serializing_if = "Option::is_none")]
        pub streams_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MetadataAuthorizationSchemesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec_urn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Metadata {
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
        pub authorization_schemes: Option<Vec<Answer200MetadataAuthorizationSchemesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub critical_subject_members: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeliveryItem {
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
    pub struct Answer200PushTransport {
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
    pub struct Answer200Push {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport: Option<Answer200PushTransport>,
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
    pub struct Answer200EventTypesItemMembersItem {
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
    pub struct Answer200EventTypesItem {
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
        pub members: Option<Vec<Answer200EventTypesItemMembersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<Vec<String>>,
        #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
        pub subject_formats: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deprecated: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectFormatsItemExampleIdentifiersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub phone_number: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectFormatsItemExample {
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
        pub identifiers: Option<Vec<Answer200SubjectFormatsItemExampleIdentifiersItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectFormatsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub example: Option<Answer200SubjectFormatsItemExample>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ComplexSubjectMembersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticationScopes {
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
    pub struct Answer200AuthenticationSchemesItem {
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
    pub struct Answer200Authentication {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Answer200AuthenticationScopes>,
        #[serde(rename = "refusedPassword", default, skip_serializing_if = "Option::is_none")]
        pub refused_password: Option<String>,
        #[serde(rename = "metadataIsOpen", default, skip_serializing_if = "Option::is_none")]
        pub metadata_is_open: Option<bool>,
        #[serde(rename = "passwordVerified", default, skip_serializing_if = "Option::is_none")]
        pub password_verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schemes: Option<Vec<Answer200AuthenticationSchemesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamsItem {
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
    pub struct Answer200EndpointsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ReachableNegativesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub answer: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200StreamDetailItemAud {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamDetailItemDelivery {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub endpoint_url: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamDetailItemSubjectsItem {
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
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamDetailItemQueueItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "deliveredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub delivered_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<sts_model_management_components_2::IssuedTokenView>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamDetailItemDeadLettersItem {
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
        pub summary: Option<sts_model_management_components_2::IssuedTokenView>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamDetailItemLogItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamDetailItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stream_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub iss: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub aud: Option<Option<Answer200StreamDetailItemAud>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub status_reason: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivery: Option<Answer200StreamDetailItemDelivery>,
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
        pub subjects: Option<Vec<Answer200StreamDetailItemSubjectsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub queue: Option<Vec<Answer200StreamDetailItemQueueItem>>,
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
        pub dead_letters: Option<Vec<Answer200StreamDetailItemDeadLettersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub log: Option<Vec<Answer200StreamDetailItemLogItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeadLettersPushes {
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
    pub struct Answer200DeadLetters {
        #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
        pub retention_s: Option<f64>,
        #[serde(rename = "maxPerStream", default, skip_serializing_if = "Option::is_none")]
        pub max_per_stream: Option<f64>,
        #[serde(rename = "deadStreamTimeoutS", default, skip_serializing_if = "Option::is_none")]
        pub dead_stream_timeout_s: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pushes: Option<Answer200DeadLettersPushes>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StreamTotals {
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
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub streams: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub installed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
        pub metadata_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metadata: Option<Answer200Metadata>,
        #[serde(rename = "signingAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub signing_algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivery: Option<Vec<Answer200DeliveryItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub push: Option<Answer200Push>,
        #[serde(rename = "eventTypes", default, skip_serializing_if = "Option::is_none")]
        pub event_types: Option<Vec<Answer200EventTypesItem>>,
        #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
        pub subject_formats: Option<Vec<Answer200SubjectFormatsItem>>,
        #[serde(rename = "complexSubjectMembers", default, skip_serializing_if = "Option::is_none")]
        pub complex_subject_members: Option<Vec<Answer200ComplexSubjectMembersItem>>,
        #[serde(rename = "criticalSubjectMembers", default, skip_serializing_if = "Option::is_none")]
        pub critical_subject_members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication: Option<Answer200Authentication>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub streams: Option<Vec<Answer200StreamsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Vec<Answer200EndpointsItem>>,
        #[serde(rename = "reachableNegatives", default, skip_serializing_if = "Option::is_none")]
        pub reachable_negatives: Option<Vec<Answer200ReachableNegativesItem>>,
        #[serde(rename = "doesNotDo", default, skip_serializing_if = "Option::is_none")]
        pub does_not_do: Option<Vec<String>>,
        #[serde(rename = "streamDetail", default, skip_serializing_if = "Option::is_none")]
        pub stream_detail: Option<Vec<Answer200StreamDetailItem>>,
        #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
        pub dead_letters: Option<Answer200DeadLetters>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub statuses: Option<Vec<String>>,
        #[serde(rename = "streamTotals", default, skip_serializing_if = "Option::is_none")]
        pub stream_totals: Option<Answer200StreamTotals>,
        #[serde(rename = "streamFilter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub stream_filter: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Drop a stream's dead letters
pub mod clear_ssf_dead_letters {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ssf/clear-dead-letters";
    pub const OPERATION_ID: &str = "clearSsfDeadLetters";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The stream.
        pub stream_id: String,
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

/// What the Shared Signals transmitter could not deliver, counted
pub mod get_ssf_dead_letters {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ssf/dead-letters";
    pub const OPERATION_ID: &str = "getSsfDeadLetters";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryDlcause {
        #[serde(rename = "push-failed")]
        PushFailed,
        #[serde(rename = "backlog-full")]
        BacklogFull,
        #[serde(rename = "declared-dead")]
        DeclaredDead,
        #[serde(rename = "dead-stream")]
        DeadStream,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dlq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dlstream: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dlcause: Option<QueryDlcause>,
        #[serde(rename = "lettersPage", default, skip_serializing_if = "Option::is_none")]
        pub letters_page: Option<i64>,
        #[serde(rename = "streamsPage", default, skip_serializing_if = "Option::is_none")]
        pub streams_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::SsfDeadLetters;
}

/// Delete a stream
pub mod delete_ssf_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ssf/delete";
    pub const OPERATION_ID: &str = "deleteSsfStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The stream.
        pub stream_id: String,
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

/// Revive a dead push stream
pub mod revive_ssf_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ssf/revive";
    pub const OPERATION_ID: &str = "reviveSsfStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The stream.
        pub stream_id: String,
        /// Optional; written on the stream's log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
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

/// Enable, pause or disable a stream
pub mod set_ssf_stream_status {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ssf/status";
    pub const OPERATION_ID: &str = "setSsfStreamStatus";

    /// The new status.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyStatus {
        #[serde(rename = "enabled")]
        Enabled,
        #[serde(rename = "paused")]
        Paused,
        #[serde(rename = "disabled")]
        Disabled,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The stream, as GET /admin-api/ssf lists it.
        pub stream_id: String,
        /// The new status.
        pub status: BodyStatus,
        /// Optional. Why, in words — it rides in the stream-updated event's
        /// `reason` member, which nothing parses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors109;
}

/// Send a Security Event Token on a stream
pub mod transmit_ssf_event {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ssf/transmit";
    pub const OPERATION_ID: &str = "transmitSsfEvent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The stream.
        pub stream_id: String,
        /// The event type URI. It must be one the stream DELIVERS — the
        /// intersection of what the receiver requested and what this transmitter
        /// supports — and a refusal lists what that is.
        #[serde(rename = "type")]
        pub type_: String,
        /// The event's own members. A verification event takes an optional `state`;
        /// a stream-updated event takes a required `status` and an optional
        /// `reason`. An unrecognised member is CARRIED with a warning rather than
        /// refused: an event vocabulary extends, and a receiver is expected to
        /// ignore what it does not know.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub payload: Option<serde_json::Map<String, serde_json::Value>>,
        /// Optional `sub_id` (RFC 9493), simple or complex. Neither SSF event takes
        /// one — both are about the STREAM — so this is here for the vocabularies
        /// that come next. Each format's member set is CLOSED and an extra member
        /// is refused by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<serde_json::Map<String, serde_json::Value>>,
        /// Optional RFC 8417 `txn`, tying several events to one act.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub txn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors109;
}

/// The federation partners whose Shared Signals this realm receives
pub mod get_partner_signals {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ssf/transmitters";
    pub const OPERATION_ID: &str = "getPartnerSignals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationship: Option<String>,
        #[serde(rename = "receivedPage", default, skip_serializing_if = "Option::is_none")]
        pub received_page: Option<i64>,
        #[serde(rename = "blocksPage", default, skip_serializing_if = "Option::is_none")]
        pub blocks_page: Option<i64>,
        #[serde(rename = "locksPage", default, skip_serializing_if = "Option::is_none")]
        pub locks_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LocksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationship: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub received: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub blocks: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locks: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub received: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub blocks: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locks: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationships: Option<Vec<sts_model_management_components_4::WithRelationshipNameKind>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub received: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesKty>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub blocks: Option<sts_model_management_components_4::WithRelationshipUsernameAt>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub locks: Option<Vec<Answer200LocksItem>>,
        #[serde(rename = "observeOnly", default, skip_serializing_if = "Option::is_none")]
        pub observe_only: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
    }
}

/// Send a transmitter-initiated verification event
pub mod verify_ssf_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ssf/verify";
    pub const OPERATION_ID: &str = "verifySsfStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The stream.
        pub stream_id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors109;
}

/// The TLS certificate's own settings
pub mod get_tls_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/tls";
    pub const OPERATION_ID: &str = "getTlsSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat2;
}

/// What this service saw of THIS request: its TLS connection, its client
/// certificate and its forwarding headers
pub mod get_tls_connection {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/tls-connection";
    pub const OPERATION_ID: &str = "getTlsConnection";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Connection {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub https: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub encrypted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub protocol: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cipher: Option<Option<String>>,
        #[serde(rename = "peerAddress", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub peer_address: Option<Option<String>>,
        #[serde(rename = "clientAddress", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_address: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateCertificate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub depth: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issuer: Option<Option<String>>,
        #[serde(rename = "serialNumber", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub serial_number: Option<Option<String>>,
        #[serde(rename = "validFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub valid_from: Option<Option<String>>,
        #[serde(rename = "validTo", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub valid_to: Option<Option<String>>,
        #[serde(rename = "subjectAltName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject_alt_name: Option<Option<String>>,
        #[serde(rename = "extendedKeyUsage", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub extended_key_usage: Option<Option<Vec<serde_json::Value>>>,
        #[serde(rename = "keySize", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub key_size: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub curve: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub fingerprint256: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pem: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateIdentity {
        #[serde(rename = "issuedHere", default, skip_serializing_if = "Option::is_none")]
        pub issued_here: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accepted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kind: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateRevocationRevoked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub depth: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub serial_hex: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reason: Option<Option<String>>,
        #[serde(rename = "reasonCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reason_code: Option<Option<f64>>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "answeredBy", default, skip_serializing_if = "Option::is_none")]
        pub answered_by: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateRevocationUnknownItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub depth: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refusable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub invalid: Option<bool>,
        #[serde(rename = "notDialled", default, skip_serializing_if = "Option::is_none")]
        pub not_dialled: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateRevocationLinksItemAuthority {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub scope: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ca: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateRevocationLinksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub depth: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub serial_hex: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issuer: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authority: Option<Answer200ClientCertificateRevocationLinksItemAuthority>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reason: Option<Option<String>>,
        #[serde(rename = "reasonCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reason_code: Option<Option<f64>>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_at: Option<Option<String>>,
        #[serde(rename = "unknownKind", default, skip_serializing_if = "Option::is_none")]
        pub unknown_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refusable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub invalid: Option<bool>,
        #[serde(rename = "noRevAvail", default, skip_serializing_if = "Option::is_none")]
        pub no_rev_avail: Option<bool>,
        #[serde(rename = "notDialled", default, skip_serializing_if = "Option::is_none")]
        pub not_dialled: Option<Vec<String>>,
        #[serde(rename = "distributionPoints", default, skip_serializing_if = "Option::is_none")]
        pub distribution_points: Option<Vec<String>>,
        #[serde(rename = "ocspOrder", default, skip_serializing_if = "Option::is_none")]
        pub ocsp_order: Option<String>,
        #[serde(rename = "answeredBy", default, skip_serializing_if = "Option::is_none")]
        pub answered_by: Option<String>,
        #[serde(rename = "crlUrl", default, skip_serializing_if = "Option::is_none")]
        pub crl_url: Option<String>,
        #[serde(rename = "crlNextUpdate", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub crl_next_update: Option<Option<String>>,
        #[serde(rename = "crlFromCache", default, skip_serializing_if = "Option::is_none")]
        pub crl_from_cache: Option<bool>,
        #[serde(rename = "deltaUrl", default, skip_serializing_if = "Option::is_none")]
        pub delta_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub indirect: Option<bool>,
        #[serde(rename = "ocspUrl", default, skip_serializing_if = "Option::is_none")]
        pub ocsp_url: Option<String>,
        #[serde(rename = "ocspFromCache", default, skip_serializing_if = "Option::is_none")]
        pub ocsp_from_cache: Option<bool>,
        #[serde(rename = "ocspResponder", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ocsp_responder: Option<Option<String>>,
        #[serde(rename = "ocspNonce", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ocsp_nonce: Option<Option<sts_model_base::unions::BoolOrString>>,
        #[serde(rename = "ocspNextUpdate", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ocsp_next_update: Option<Option<String>>,
        #[serde(rename = "ocspResponderStatus", default, skip_serializing_if = "Option::is_none")]
        pub ocsp_responder_status: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateRevocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checked: Option<bool>,
        #[serde(rename = "notDialled", default, skip_serializing_if = "Option::is_none")]
        pub not_dialled: Option<Vec<String>>,
        #[serde(rename = "noRevAvail", default, skip_serializing_if = "Option::is_none")]
        pub no_rev_avail: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<Answer200ClientCertificateRevocationRevoked>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unknown: Option<Vec<Answer200ClientCertificateRevocationUnknownItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<Answer200ClientCertificateRevocationLinksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(rename = "policyConfigured", default, skip_serializing_if = "Option::is_none")]
        pub policy_configured: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificateRevocationStatus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub checked: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presented: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(rename = "handshakeVerified", default, skip_serializing_if = "Option::is_none")]
        pub handshake_verified: Option<bool>,
        #[serde(rename = "authorizationError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub authorization_error: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Answer200ClientCertificateCertificate>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub thumbprint: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identity: Option<Answer200ClientCertificateIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revocation: Option<Answer200ClientCertificateRevocation>,
        #[serde(rename = "revocationStatus", default, skip_serializing_if = "Option::is_none")]
        pub revocation_status: Option<Answer200ClientCertificateRevocationStatus>,
        #[serde(rename = "signIn", default, skip_serializing_if = "Option::is_none")]
        pub sign_in: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ForwardedSocket {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scheme: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub encrypted: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ForwardedForwardingItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub header: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ForwardedClientCertificateHeadersHeadersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub header: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ForwardedClientCertificateHeaders {
        #[serde(rename = "readByThisService", default, skip_serializing_if = "Option::is_none")]
        pub read_by_this_service: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seen: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub headers: Option<Vec<Answer200ForwardedClientCertificateHeadersHeadersItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Forwarded {
        #[serde(rename = "trustProxy", default, skip_serializing_if = "Option::is_none")]
        pub trust_proxy: Option<bool>,
        #[serde(rename = "trustedProxies", default, skip_serializing_if = "Option::is_none")]
        pub trusted_proxies: Option<Vec<String>>,
        #[serde(rename = "rangesConfigured", default, skip_serializing_if = "Option::is_none")]
        pub ranges_configured: Option<f64>,
        #[serde(rename = "rangesUsable", default, skip_serializing_if = "Option::is_none")]
        pub ranges_usable: Option<f64>,
        #[serde(rename = "peerIsTrustedProxy", default, skip_serializing_if = "Option::is_none")]
        pub peer_is_trusted_proxy: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub believed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub socket: Option<Answer200ForwardedSocket>,
        #[serde(rename = "effectiveBaseUrl", default, skip_serializing_if = "Option::is_none")]
        pub effective_base_url: Option<String>,
        #[serde(rename = "whatItMeans", default, skip_serializing_if = "Option::is_none")]
        pub what_it_means: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forwarding: Option<Vec<Answer200ForwardedForwardingItem>>,
        #[serde(rename = "clientCertificateHeaders", default, skip_serializing_if = "Option::is_none")]
        pub client_certificate_headers: Option<Answer200ForwardedClientCertificateHeaders>,
        #[serde(rename = "proxyMustSanitize", default, skip_serializing_if = "Option::is_none")]
        pub proxy_must_sanitize: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connection: Option<Answer200Connection>,
        #[serde(rename = "clientCertificate", default, skip_serializing_if = "Option::is_none")]
        pub client_certificate: Option<Answer200ClientCertificate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forwarded: Option<Answer200Forwarded>,
    }
}

/// Every client-certificate trust anchor, and where each came from
pub mod get_truststore {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/tls/trust";
    pub const OPERATION_ID: &str = "getTruststore";

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
    pub struct Answer200Doors {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub console: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub api: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Notes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persisted: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub effect: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revocation: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub installed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub anchors: Option<sts_model_management_components_4::WithOkMessageErrors126>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(rename = "fromFile", default, skip_serializing_if = "Option::is_none")]
        pub from_file: Option<i64>,
        #[serde(rename = "atRuntime", default, skip_serializing_if = "Option::is_none")]
        pub at_runtime: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<i64>,
        #[serde(rename = "anchorsFile", default, skip_serializing_if = "Option::is_none")]
        pub anchors_file: Option<String>,
        #[serde(rename = "loadedFromFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub loaded_from_file: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persisted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub doors: Option<Answer200Doors>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<Answer200Notes>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
    }
}

/// Trust client certificates issued by one or more CAs
pub mod add_trust_anchors {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tls/trust/add";
    pub const OPERATION_ID: &str = "addTrustAnchors";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// One or more PEM certificates, concatenated. An array of PEM strings is
        /// accepted too.
        pub certificates: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors127;
}

/// Stop trusting one anchor, named by its fingerprint
pub mod remove_trust_anchor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tls/trust/remove";
    pub const OPERATION_ID: &str = "removeTrustAnchor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The anchor's SHA-256 fingerprint, as `GET /admin-api/tls/trust` lists it
        /// in `fingerprint256`.
        pub fingerprint: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors128;
}

/// How long tokens issued here are good for
pub mod get_token_lifetimes {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/token-lifetimes";
    pub const OPERATION_ID: &str = "getTokenLifetimes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::TokenLifetimes;
}

/// Put the six back
pub mod reset_token_lifetimes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/token-lifetimes/defaults";
    pub const OPERATION_ID: &str = "resetTokenLifetimes";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors71;
}

/// Set one or more of the six
pub mod set_token_lifetimes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/token-lifetimes/set";
    pub const OPERATION_ID: &str = "setTokenLifetimes";

    /// One property per setting, named by its dot path. THESE AND NO OTHERS, and
    /// the list below is BUILT from the one this action refuses against rather than
    /// typed beside it: the door refuses anything outside it BY NAME, which is the
    /// whole reason it exists beside `POST /config/set-many` — that one IGNORES a
    /// key it does not know, which is right for a form posting a section and wrong
    /// for a caller who misspelt a lifetime. A document short by one is then a
    /// caller refused for following it.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Access token lifetime (s)
        #[serde(rename = "oauth2.accessTokenTtlS", default, skip_serializing_if = "Option::is_none")]
        pub oauth2_access_token_ttl_s: Option<i64>,
        /// ID Token lifetime (s)
        #[serde(rename = "oauth2.idTokenTtlS", default, skip_serializing_if = "Option::is_none")]
        pub oauth2_id_token_ttl_s: Option<i64>,
        /// Refresh token lifetime (s)
        #[serde(rename = "oauth2.refreshTokenTtlS", default, skip_serializing_if = "Option::is_none")]
        pub oauth2_refresh_token_ttl_s: Option<i64>,
        /// Refresh token idle timeout (s)
        #[serde(rename = "oauth2.refreshIdleSeconds", default, skip_serializing_if = "Option::is_none")]
        pub oauth2_refresh_idle_seconds: Option<i64>,
        /// Revoke refresh tokens on sign-out
        #[serde(rename = "oauth2.revokeRefreshOnLogout", default, skip_serializing_if = "Option::is_none")]
        pub oauth2_revoke_refresh_on_logout: Option<bool>,
        /// Token clock skew (s)
        #[serde(rename = "oauth2.clockSkewS", default, skip_serializing_if = "Option::is_none")]
        pub oauth2_clock_skew_s: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors70;
}

/// Everything issued, grouped into what came back in one reply
pub mod get_issued {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/tokens";
    pub const OPERATION_ID: &str = "getIssued";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFamily {
        #[serde(rename = "token")]
        Token,
        #[serde(rename = "assertion")]
        Assertion,
        #[serde(rename = "ticket")]
        Ticket,
        #[serde(rename = "svid")]
        Svid,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryKind {
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "refresh_token")]
        RefreshToken,
        #[serde(rename = "userinfo_response")]
        UserinfoResponse,
        #[serde(rename = "request_object")]
        RequestObject,
        #[serde(rename = "gnap_access_token")]
        GnapAccessToken,
        #[serde(rename = "SAML 2.0")]
        Saml20,
        #[serde(rename = "SAML 1.1")]
        Saml11,
        #[serde(rename = "Kerberos TGT")]
        KerberosTgt,
        #[serde(rename = "Kerberos service ticket")]
        KerberosServiceTicket,
        #[serde(rename = "SVID (X.509)")]
        SvidX509,
        #[serde(rename = "SVID (JWT)")]
        SvidJwt,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryState {
        #[serde(rename = "valid")]
        Valid,
        #[serde(rename = "expired")]
        Expired,
        #[serde(rename = "revoked")]
        Revoked,
        #[serde(rename = "not yet valid")]
        NotYetValid,
        #[serde(rename = "no expiry stated")]
        NoExpiryStated,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<QueryFamily>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<QueryKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<QueryState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::IssuedList;
}

/// One credential and every generation behind it
pub mod get_credential_lineage {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/tokens/credential";
    pub const OPERATION_ID: &str = "getCredentialLineage";

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
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generations: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exchanges: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parties: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GenerationsItemActInitial {
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
    pub struct Answer200GenerationsItemActIntermediary {
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
    pub struct Answer200GenerationsItemActTarget {
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
    pub struct Answer200GenerationsItemActConsumedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GenerationsItemActProducedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GenerationsItemAct {
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
        pub initial: Option<Answer200GenerationsItemActInitial>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<Answer200GenerationsItemActIntermediary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<Answer200GenerationsItemActTarget>,
        #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
        pub authorized_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consumed: Option<Vec<Answer200GenerationsItemActConsumedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub produced: Option<Vec<Answer200GenerationsItemActProducedItem>>,
        #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
        pub chain_key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GenerationsItemConsumedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GenerationsItemOpaqueItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GenerationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub credential: Option<Option<sts_model_management_components_2::IssuedRecord>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub act: Option<Answer200GenerationsItemAct>,
        #[serde(rename = "producedByExchange", default, skip_serializing_if = "Option::is_none")]
        pub produced_by_exchange: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consumed: Option<Vec<Answer200GenerationsItemConsumedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub opaque: Option<Vec<Answer200GenerationsItemOpaqueItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
        #[serde(rename = "originLabel", default, skip_serializing_if = "Option::is_none")]
        pub origin_label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuancesItemFlow {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flow: Option<String>,
        #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
        pub match_: Option<String>,
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
    pub struct Answer200IssuancesItemAudience {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub registered: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuancesItemAudiencesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub registered: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuancesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<sts_model_management_components_2::IssuedRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flow: Option<Answer200IssuancesItemFlow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audience: Option<Answer200IssuancesItemAudience>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audiences: Option<Vec<Answer200IssuancesItemAudiencesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WallsItemCredential {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WallsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub act: Option<sts_model_management_components_4::WithSeqOriginAt>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credential: Option<Answer200WallsItemCredential>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GraphRealm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
        pub is_default: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GraphNodesItemRealm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
        pub is_default: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GraphNodesItemRoles {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub initial: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediary: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GraphNodesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200GraphNodesItemRealm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Answer200GraphNodesItemRoles>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flows: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<i64>,
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
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GraphEdgesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
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
        #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
        pub authorized_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub consumed: Option<sts_model_management_components_4::WithOkMessageErrors63>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub produced: Option<sts_model_management_components_4::WithOkMessageErrors63>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skipped: Option<Vec<String>>,
        #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
        pub chain_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<String>>,
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
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor: Option<String>,
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
        pub audience: Option<String>,
        #[serde(rename = "audienceRegistered", default, skip_serializing_if = "Option::is_none")]
        pub audience_registered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mechanism: Option<String>,
        #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
        pub set_on: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub used: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GraphTokensItem {
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
    pub struct Answer200Graph {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<Answer200GraphRealm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<Vec<Answer200GraphNodesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub edges: Option<Vec<Answer200GraphEdgesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tokens: Option<Vec<Answer200GraphTokensItem>>,
        #[serde(rename = "tokensLeftOff", default, skip_serializing_if = "Option::is_none")]
        pub tokens_left_off: Option<i64>,
        #[serde(rename = "maxTokenRows", default, skip_serializing_if = "Option::is_none")]
        pub max_token_rows: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chains: Option<i64>,
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
    pub struct Answer200Facts {
        /// Who in the answer has a user page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<serde_json::Map<String, serde_json::Value>>,
        /// Which values in the answer are applications.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub apps: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub identifier: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub held: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub credential: Option<Option<sts_model_management_components_2::IssuedRecord>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generations: Option<Vec<Answer200GenerationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origins: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuances: Option<Vec<Answer200IssuancesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub walls: Option<Vec<Answer200WallsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub truncated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acts: Option<Vec<sts_model_management_components_4::WithSeqOriginAt>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub graph: Option<Answer200Graph>,
        #[serde(rename = "maxGenerations", default, skip_serializing_if = "Option::is_none")]
        pub max_generations: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drawing: Option<Answer200Drawing>,
        /// How each node of the graph is drawn.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub looks: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub svg: Option<String>,
        #[serde(rename = "subjectKey", default, skip_serializing_if = "Option::is_none")]
        pub subject_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facts: Option<Answer200Facts>,
    }
}

/// Un-revoke one token (NON-SPEC)
pub mod restore_token {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/restore";
    pub const OPERATION_ID: &str = "restoreToken";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A jti, or a whole JWT.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<String>,
        /// Accepted for `target`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
        /// Accepted for `target`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
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
        pub jti: Option<String>,
    }
}

/// Stop disowning one assertion, ticket or SVID (NON-SPEC)
pub mod restore_issued_artifact {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/restore-artifact";
    pub const OPERATION_ID: &str = "restoreIssuedArtifact";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `key` off a row of GET /admin-api/tokens.
        pub artifact: String,
        /// Accepted for `artifact`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors64;
}

/// Un-revoke every revocable credential in one issuance (NON-SPEC)
pub mod restore_issued_set {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/restore-set";
    pub const OPERATION_ID: &str = "restoreIssuedSet";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `setKey` off a row of GET /admin-api/tokens.
        pub set: String,
        /// Accepted for `set`.
        #[serde(rename = "setKey", default, skip_serializing_if = "Option::is_none")]
        pub set_key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors65;
}

/// Revoke one token
pub mod revoke_token {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke";
    pub const OPERATION_ID: &str = "revokeToken";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A jti, or a whole JWT.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<String>,
        /// Accepted for `target`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
        /// Accepted for `target`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
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
        pub jti: Option<String>,
    }
}

/// Revoke every access token, ID Token and refresh token
pub mod revoke_all_tokens {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke-all";
    pub const OPERATION_ID: &str = "revokeAllTokens";

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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }
}

/// Disown one assertion, ticket or SVID (RECORD ONLY)
pub mod revoke_issued_artifact {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke-artifact";
    pub const OPERATION_ID: &str = "revokeIssuedArtifact";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `key` off a row of GET /admin-api/tokens. This service's own handle
        /// and NOT the protocol's — a Kerberos ticket carries no identifier anybody
        /// can quote, so `identifier` cannot address every row and this can.
        pub artifact: String,
        /// Accepted for `artifact`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors64;
}

/// Revoke every token of one kind
pub mod revoke_tokens_by_kind {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke-kind";
    pub const OPERATION_ID: &str = "revokeTokensByKind";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "id_token")]
        IdToken,
        #[serde(rename = "refresh_token")]
        RefreshToken,
        #[serde(rename = "gnap_access_token")]
        GnapAccessToken,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub kind: BodyKind,
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
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }
}

/// Revoke every revocable credential in one issuance
pub mod revoke_issued_set {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke-set";
    pub const OPERATION_ID: &str = "revokeIssuedSet";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `setKey` off a row of GET /admin-api/tokens.
        pub set: String,
        /// Accepted for `set`.
        #[serde(rename = "setKey", default, skip_serializing_if = "Option::is_none")]
        pub set_key: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors65;
}

/// Revoke everything for one subject or username
pub mod revoke_tokens_by_subject {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke-subject";
    pub const OPERATION_ID: &str = "revokeTokensBySubject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub subject: String,
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
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }
}

/// Revoke everything for one identity, under every spelling
pub mod revoke_tokens_by_user {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/tokens/revoke-user";
    pub const OPERATION_ID: &str = "revokeTokensByUser";

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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }
}

/// One issuance, and every credential it carried
pub mod get_issued_set {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/tokens/set";
    pub const OPERATION_ID: &str = "getIssuedSet";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::IssuedSetDetail;
}

/// The authenticator-app second factor's settings
pub mod get_totp_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/totp";
    pub const OPERATION_ID: &str = "getTotpSettings";

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
        pub status: Option<sts_model_management_components_4::WithOfferedDigitsSecretBits>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// UMA 2.0: resource servers, resources, tickets, RPTs, pending approvals, an
/// owner, the what-if, settings
pub mod get_uma {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/uma";
    pub const OPERATION_ID: &str = "getUma";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub party: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "resourcesPage", default, skip_serializing_if = "Option::is_none")]
        pub resources_page: Option<i64>,
        #[serde(rename = "ticketsPage", default, skip_serializing_if = "Option::is_none")]
        pub tickets_page: Option<i64>,
        #[serde(rename = "rptsPage", default, skip_serializing_if = "Option::is_none")]
        pub rpts_page: Option<i64>,
        #[serde(rename = "pendingPage", default, skip_serializing_if = "Option::is_none")]
        pub pending_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Resources {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<sts_model_management_components_4::WithIdStateOwner>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TicketsRowsItemPermissionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TicketsRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<Answer200TicketsRowsItemPermissionsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<String>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<f64>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Tickets {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200TicketsRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RptsRowsItemPermissionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RptsRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
        #[serde(rename = "requestingParty", default, skip_serializing_if = "Option::is_none")]
        pub requesting_party: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
        pub resource_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub permissions: Option<Vec<Answer200RptsRowsItemPermissionsItem>>,
        #[serde(rename = "upgradedFrom", default, skip_serializing_if = "Option::is_none")]
        pub upgraded_from: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
        pub created_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exp: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Rpts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RptsRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Pending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<sts_model_management_components_4::WithIdResourceIdScopes>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OwnerDocumentCustomItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OwnerDocument {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stored: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rules: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shares: Option<Vec<sts_model_management_components_4::WithIdResourceIdScopes2>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custom: Option<Vec<Answer200OwnerDocumentCustomItem>>,
        #[serde(rename = "alfaEditing", default, skip_serializing_if = "Option::is_none")]
        pub alfa_editing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alfa: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Owner {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(rename = "ownsResources", default, skip_serializing_if = "Option::is_none")]
        pub owns_resources: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub editable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<sts_model_management_components_4::WithIdStateOwner>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<Answer200OwnerDocument>,
        #[serde(rename = "documentXml", default, skip_serializing_if = "Option::is_none")]
        pub document_xml: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<sts_model_management_components_4::WithIdResourceIdScopes>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WhatIfAsked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub party: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WhatIfLayersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub layer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decision: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approval: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WhatIf {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<Answer200WhatIfAsked>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub layers: Option<Vec<Answer200WhatIfLayersItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProtocolEndpointsItem {
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specifications: Option<Vec<String>>,
        /// The realm's RFC 8414 authorization server metadata with UMA's members
        /// added (`oauth2.asMetadata()`), or nothing when UMA is off. Its members
        /// are an IANA registry's and each is conditional on a setting, and GET
        /// /.well-known/uma2-configuration is where it is specified.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<serde_json::Value>,
        #[serde(rename = "resourceServers", default, skip_serializing_if = "Option::is_none")]
        pub resource_servers: Option<sts_model_management_components_4::WithIdNameType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<Answer200Resources>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tickets: Option<Answer200Tickets>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rpts: Option<Answer200Rpts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<Answer200Pending>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<Answer200Owner>,
        #[serde(rename = "whatIf", default, skip_serializing_if = "Option::is_none")]
        pub what_if: Option<Answer200WhatIf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub monitor: Option<sts_model_management_components_2::MonitorValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue3>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<Vec<Answer200ProtocolEndpointsItem>>,
    }
}

/// Delete a registered UMA resource
pub mod delete_uma_resource {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/delete-resource";
    pub const OPERATION_ID: &str = "deleteUmaResource";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The resource's _id.
        pub resource: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors182;
}

/// Stop an application being a UMA resource server
pub mod disable_uma_resource_server {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/disable-resource-server";
    pub const OPERATION_ID: &str = "disableUmaResourceServer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application's identifier.
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors181;
}

/// Make an application a UMA resource server
pub mod enable_uma_resource_server {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/enable-resource-server";
    pub const OPERATION_ID: &str = "enableUmaResourceServer";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application's identifier.
        pub application: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors181;
}

/// The UMA PEP's counts and what each resource server holds
pub mod get_uma_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/uma/monitor";
    pub const OPERATION_ID: &str = "getUmaMonitor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Totals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resources: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tickets: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rpts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pep: Option<sts_model_management_components_2::MonitorValue>,
        #[serde(rename = "resourceServers", default, skip_serializing_if = "Option::is_none")]
        pub resource_servers: Option<sts_model_management_components_4::WithIdNameType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
    }
}

/// Approve a request waiting for an application
pub mod approve_uma_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/owner-approve";
    pub const OPERATION_ID: &str = "approveUmaRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application whose document it is; it must carry umaOwnsResources
        /// TRUE.
        pub owner: String,
        /// The waiting request's id.
        pub pending: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors184;
}

/// Refuse a request waiting for an application
pub mod refuse_uma_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/owner-refuse";
    pub const OPERATION_ID: &str = "refuseUmaRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application whose document it is; it must carry umaOwnsResources
        /// TRUE.
        pub owner: String,
        /// The waiting request's id.
        pub pending: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors184;
}

/// Share an application's resource
pub mod share_uma_resource {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/owner-share";
    pub const OPERATION_ID: &str = "shareUmaResource";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyScope {
        V1(Vec<String>),
        String(String),
    }

    /// Who it is shared with.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRecipientKind {
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
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application whose document it is; it must carry umaOwnsResources
        /// TRUE.
        pub owner: String,
        /// The resource's _id.
        pub resource: String,
        /// The scopes, a list or one string.
        pub scope: BodyScope,
        /// Who it is shared with.
        #[serde(rename = "recipientKind")]
        pub recipient_kind: BodyRecipientKind,
        /// A username, a group, or a claim's value; nothing for realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recipient: Option<String>,
        /// For a claim share, its name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claim: Option<String>,
        /// When it ends (a date), or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires: Option<String>,
        /// An authentication context the requesting party must have.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acr: Option<String>,
        /// on: ask the owner each time.
        #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
        pub ask_me: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors183;
}

/// Remove a share from an application's document
pub mod unshare_uma_resource {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/owner-unshare";
    pub const OPERATION_ID: &str = "unshareUmaResource";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application whose document it is; it must carry umaOwnsResources
        /// TRUE.
        pub owner: String,
        /// The share's id.
        pub share: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors183;
}

/// Revoke one RPT
pub mod revoke_uma_rpt {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/revoke-rpt";
    pub const OPERATION_ID: &str = "revokeUmaRpt";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The RPT's jti.
        pub rpt: String,
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
        pub rpt: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
    }
}

/// Let an application own UMA resources, or not
pub mod set_uma_owns_resources {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/uma/set-owns-resources";
    pub const OPERATION_ID: &str = "setUmaOwnsResources";

    /// TRUE, or FALSE to clear it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyValue {
        #[serde(rename = "TRUE")]
        True,
        #[serde(rename = "FALSE")]
        False,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application's identifier.
        pub application: String,
        /// TRUE, or FALSE to clear it.
        pub value: BodyValue,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors181;
}

/// Every RFC 7523 and RFC 7522 assertion this realm has accepted and that has
/// not yet expired
pub mod get_used_assertions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/used-assertions";
    pub const OPERATION_ID: &str = "getUsedAssertions";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "jwt")]
        Jwt,
        #[serde(rename = "openid2")]
        Openid2,
        #[serde(rename = "saml")]
        Saml,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "saml-message")]
        SamlMessage,
        #[serde(rename = "attestation-challenge")]
        AttestationChallenge,
        #[serde(rename = "wss-message")]
        WssMessage,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryUse {
        #[serde(rename = "steam-assertion")]
        SteamAssertion,
        #[serde(rename = "client-authentication")]
        ClientAuthentication,
        #[serde(rename = "authorization-grant")]
        AuthorizationGrant,
        #[serde(rename = "federated-sign-in")]
        FederatedSignIn,
        #[serde(rename = "request-object")]
        RequestObject,
        #[serde(rename = "ciba-request")]
        CibaRequest,
        #[serde(rename = "federated-logout")]
        FederatedLogout,
        #[serde(rename = "provider-notification")]
        ProviderNotification,
        #[serde(rename = "client-attestation-pop")]
        ClientAttestationPop,
        #[serde(rename = "token-exchange")]
        TokenExchange,
        #[serde(rename = "wstrust-requester")]
        WstrustRequester,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryState {
        #[serde(rename = "reserved")]
        Reserved,
        #[serde(rename = "spent")]
        Spent,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        pub use_: Option<QueryUse>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<QueryState>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        pub use_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(rename = "formatLabel", default, skip_serializing_if = "Option::is_none")]
        pub format_label: Option<String>,
        #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
        pub use_: Option<String>,
        #[serde(rename = "useLabel", default, skip_serializing_if = "Option::is_none")]
        pub use_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none")]
        pub used_at: Option<f64>,
        #[serde(rename = "spentAt", default, skip_serializing_if = "Option::is_none")]
        pub spent_at: Option<f64>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persistent: Option<bool>,
        #[serde(rename = "atomicAcrossProcesses", default, skip_serializing_if = "Option::is_none")]
        pub atomic_across_processes: Option<bool>,
        #[serde(rename = "storeNote", default, skip_serializing_if = "Option::is_none")]
        pub store_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cap: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub live: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<i64>,
        #[serde(rename = "searchNote", default, skip_serializing_if = "Option::is_none")]
        pub search_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        /// Each format and what it is called.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub formats: Option<serde_json::Map<String, serde_json::Value>>,
        /// Each use and what it is called.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uses: Option<serde_json::Map<String, serde_json::Value>>,
        /// Each state and what it means.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub states: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub param: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub noun: Option<String>,
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
}

/// What every UserInfo response will carry, and what a client may ask it for
pub mod get_user_info_claims {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/userinfo-claims";
    pub const OPERATION_ID: &str = "getUserInfoClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::UserInfoClaimSets;
}

/// Add one claim to one set
pub mod add_user_info_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/add";
    pub const OPERATION_ID: &str = "addUserInfoClaim";

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
        pub set: String,
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
pub mod add_user_info_attribute_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/add-attribute-claim";
    pub const OPERATION_ID: &str = "addUserInfoAttributeClaim";

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
        pub set: String,
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
pub mod set_user_info_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/attributes";
    pub const OPERATION_ID: &str = "setUserInfoClaimAttributes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: String,
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
pub mod select_all_user_info_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/attributes-all";
    pub const OPERATION_ID: &str = "selectAllUserInfoClaimAttributes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: String,
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
pub mod clear_user_info_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/attributes-clear";
    pub const OPERATION_ID: &str = "clearUserInfoClaimAttributes";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: String,
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
pub mod clear_user_info_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/clear";
    pub const OPERATION_ID: &str = "clearUserInfoClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: String,
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
pub mod remove_user_info_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/remove";
    pub const OPERATION_ID: &str = "removeUserInfoClaim";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: String,
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
pub mod replace_user_info_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/userinfo-claims/replace";
    pub const OPERATION_ID: &str = "replaceUserInfoClaims";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub set: String,
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

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "sendBroadcast" => Some(serde_json::from_value::<send_broadcast::Body>(value.clone()).map(|_| ())),
        "endLiveSessions" => Some(serde_json::from_value::<end_live_sessions::Body>(value.clone()).map(|_| ())),
        "globalLogout" => Some(serde_json::from_value::<global_logout::Body>(value.clone()).map(|_| ())),
        "clearKerberosSignOut" => Some(serde_json::from_value::<clear_kerberos_sign_out::Body>(value.clone()).map(|_| ())),
        "restoreLoggedOutToken" => Some(serde_json::from_value::<restore_logged_out_token::Body>(value.clone()).map(|_| ())),
        "retryBackchannelDelivery" => Some(serde_json::from_value::<retry_backchannel_delivery::Body>(value.clone()).map(|_| ())),
        "createRealm" => Some(serde_json::from_value::<create_realm::Body>(value.clone()).map(|_| ())),
        "removeRealm" => Some(serde_json::from_value::<remove_realm::Body>(value.clone()).map(|_| ())),
        "setRealmSetting" => Some(serde_json::from_value::<set_realm_setting::Body>(value.clone()).map(|_| ())),
        "unsetRealmSetting" => Some(serde_json::from_value::<unset_realm_setting::Body>(value.clone()).map(|_| ())),
        "updateRealm" => Some(serde_json::from_value::<update_realm::Body>(value.clone()).map(|_| ())),
        "revokeSession" => Some(serde_json::from_value::<revoke_session::Body>(value.clone()).map(|_| ())),
        "clearSignalsInbox" => Some(serde_json::from_value::<clear_signals_inbox::Body>(value.clone()).map(|_| ())),
        "clearSsfDeadLetters" => Some(serde_json::from_value::<clear_ssf_dead_letters::Body>(value.clone()).map(|_| ())),
        "deleteSsfStream" => Some(serde_json::from_value::<delete_ssf_stream::Body>(value.clone()).map(|_| ())),
        "reviveSsfStream" => Some(serde_json::from_value::<revive_ssf_stream::Body>(value.clone()).map(|_| ())),
        "setSsfStreamStatus" => Some(serde_json::from_value::<set_ssf_stream_status::Body>(value.clone()).map(|_| ())),
        "transmitSsfEvent" => Some(serde_json::from_value::<transmit_ssf_event::Body>(value.clone()).map(|_| ())),
        "verifySsfStream" => Some(serde_json::from_value::<verify_ssf_stream::Body>(value.clone()).map(|_| ())),
        "addTrustAnchors" => Some(serde_json::from_value::<add_trust_anchors::Body>(value.clone()).map(|_| ())),
        "removeTrustAnchor" => Some(serde_json::from_value::<remove_trust_anchor::Body>(value.clone()).map(|_| ())),
        "resetTokenLifetimes" => Some(serde_json::from_value::<reset_token_lifetimes::Body>(value.clone()).map(|_| ())),
        "setTokenLifetimes" => Some(serde_json::from_value::<set_token_lifetimes::Body>(value.clone()).map(|_| ())),
        "restoreToken" => Some(serde_json::from_value::<restore_token::Body>(value.clone()).map(|_| ())),
        "restoreIssuedArtifact" => Some(serde_json::from_value::<restore_issued_artifact::Body>(value.clone()).map(|_| ())),
        "restoreIssuedSet" => Some(serde_json::from_value::<restore_issued_set::Body>(value.clone()).map(|_| ())),
        "revokeToken" => Some(serde_json::from_value::<revoke_token::Body>(value.clone()).map(|_| ())),
        "revokeAllTokens" => Some(serde_json::from_value::<revoke_all_tokens::Body>(value.clone()).map(|_| ())),
        "revokeIssuedArtifact" => Some(serde_json::from_value::<revoke_issued_artifact::Body>(value.clone()).map(|_| ())),
        "revokeTokensByKind" => Some(serde_json::from_value::<revoke_tokens_by_kind::Body>(value.clone()).map(|_| ())),
        "revokeIssuedSet" => Some(serde_json::from_value::<revoke_issued_set::Body>(value.clone()).map(|_| ())),
        "revokeTokensBySubject" => Some(serde_json::from_value::<revoke_tokens_by_subject::Body>(value.clone()).map(|_| ())),
        "revokeTokensByUser" => Some(serde_json::from_value::<revoke_tokens_by_user::Body>(value.clone()).map(|_| ())),
        "deleteUmaResource" => Some(serde_json::from_value::<delete_uma_resource::Body>(value.clone()).map(|_| ())),
        "disableUmaResourceServer" => Some(serde_json::from_value::<disable_uma_resource_server::Body>(value.clone()).map(|_| ())),
        "enableUmaResourceServer" => Some(serde_json::from_value::<enable_uma_resource_server::Body>(value.clone()).map(|_| ())),
        "approveUmaRequest" => Some(serde_json::from_value::<approve_uma_request::Body>(value.clone()).map(|_| ())),
        "refuseUmaRequest" => Some(serde_json::from_value::<refuse_uma_request::Body>(value.clone()).map(|_| ())),
        "shareUmaResource" => Some(serde_json::from_value::<share_uma_resource::Body>(value.clone()).map(|_| ())),
        "unshareUmaResource" => Some(serde_json::from_value::<unshare_uma_resource::Body>(value.clone()).map(|_| ())),
        "revokeUmaRpt" => Some(serde_json::from_value::<revoke_uma_rpt::Body>(value.clone()).map(|_| ())),
        "setUmaOwnsResources" => Some(serde_json::from_value::<set_uma_owns_resources::Body>(value.clone()).map(|_| ())),
        "addUserInfoClaim" => Some(serde_json::from_value::<add_user_info_claim::Body>(value.clone()).map(|_| ())),
        "addUserInfoAttributeClaim" => Some(serde_json::from_value::<add_user_info_attribute_claim::Body>(value.clone()).map(|_| ())),
        "setUserInfoClaimAttributes" => Some(serde_json::from_value::<set_user_info_claim_attributes::Body>(value.clone()).map(|_| ())),
        "selectAllUserInfoClaimAttributes" => Some(serde_json::from_value::<select_all_user_info_claim_attributes::Body>(value.clone()).map(|_| ())),
        "clearUserInfoClaimAttributes" => Some(serde_json::from_value::<clear_user_info_claim_attributes::Body>(value.clone()).map(|_| ())),
        "clearUserInfoClaims" => Some(serde_json::from_value::<clear_user_info_claims::Body>(value.clone()).map(|_| ())),
        "removeUserInfoClaim" => Some(serde_json::from_value::<remove_user_info_claim::Body>(value.clone()).map(|_| ())),
        "replaceUserInfoClaims" => Some(serde_json::from_value::<replace_user_info_claims::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getConsoleAnnouncements", 200) => Some(serde_json::from_value::<get_console_announcements::Answer200>(value.clone()).map(|_| ())),
        ("getBroadcast", 200) => Some(serde_json::from_value::<get_broadcast::Answer200>(value.clone()).map(|_| ())),
        ("sendBroadcast", 200) => Some(serde_json::from_value::<send_broadcast::Answer200>(value.clone()).map(|_| ())),
        ("getLiveSessions", 200) => Some(serde_json::from_value::<get_live_sessions::Answer200>(value.clone()).map(|_| ())),
        ("endLiveSessions", 200) => Some(serde_json::from_value::<end_live_sessions::Answer200>(value.clone()).map(|_| ())),
        ("globalLogout", 200) => Some(serde_json::from_value::<global_logout::Answer200>(value.clone()).map(|_| ())),
        ("clearKerberosSignOut", 200) => Some(serde_json::from_value::<clear_kerberos_sign_out::Answer200>(value.clone()).map(|_| ())),
        ("restoreLoggedOutToken", 200) => Some(serde_json::from_value::<restore_logged_out_token::Answer200>(value.clone()).map(|_| ())),
        ("retryBackchannelDelivery", 200) => Some(serde_json::from_value::<retry_backchannel_delivery::Answer200>(value.clone()).map(|_| ())),
        ("getRealms", 200) => Some(serde_json::from_value::<get_realms::Answer200>(value.clone()).map(|_| ())),
        ("createRealm", 200) => Some(serde_json::from_value::<create_realm::Answer200>(value.clone()).map(|_| ())),
        ("removeRealm", 200) => Some(serde_json::from_value::<remove_realm::Answer200>(value.clone()).map(|_| ())),
        ("setRealmSetting", 200) => Some(serde_json::from_value::<set_realm_setting::Answer200>(value.clone()).map(|_| ())),
        ("unsetRealmSetting", 200) => Some(serde_json::from_value::<unset_realm_setting::Answer200>(value.clone()).map(|_| ())),
        ("updateRealm", 200) => Some(serde_json::from_value::<update_realm::Answer200>(value.clone()).map(|_| ())),
        ("getSessions", 200) => Some(serde_json::from_value::<get_sessions::Answer200>(value.clone()).map(|_| ())),
        ("endAllSessions", 200) => Some(serde_json::from_value::<end_all_sessions::Answer200>(value.clone()).map(|_| ())),
        ("revokeSession", 200) => Some(serde_json::from_value::<revoke_session::Answer200>(value.clone()).map(|_| ())),
        ("getSignals", 200) => Some(serde_json::from_value::<get_signals::Answer200>(value.clone()).map(|_| ())),
        ("clearSignalsInbox", 200) => Some(serde_json::from_value::<clear_signals_inbox::Answer200>(value.clone()).map(|_| ())),
        ("getSsf", 200) => Some(serde_json::from_value::<get_ssf::Answer200>(value.clone()).map(|_| ())),
        ("clearSsfDeadLetters", 200) => Some(serde_json::from_value::<clear_ssf_dead_letters::Answer200>(value.clone()).map(|_| ())),
        ("getSsfDeadLetters", 200) => Some(serde_json::from_value::<get_ssf_dead_letters::Answer200>(value.clone()).map(|_| ())),
        ("deleteSsfStream", 200) => Some(serde_json::from_value::<delete_ssf_stream::Answer200>(value.clone()).map(|_| ())),
        ("reviveSsfStream", 200) => Some(serde_json::from_value::<revive_ssf_stream::Answer200>(value.clone()).map(|_| ())),
        ("setSsfStreamStatus", 200) => Some(serde_json::from_value::<set_ssf_stream_status::Answer200>(value.clone()).map(|_| ())),
        ("transmitSsfEvent", 200) => Some(serde_json::from_value::<transmit_ssf_event::Answer200>(value.clone()).map(|_| ())),
        ("getPartnerSignals", 200) => Some(serde_json::from_value::<get_partner_signals::Answer200>(value.clone()).map(|_| ())),
        ("verifySsfStream", 200) => Some(serde_json::from_value::<verify_ssf_stream::Answer200>(value.clone()).map(|_| ())),
        ("getTlsSettings", 200) => Some(serde_json::from_value::<get_tls_settings::Answer200>(value.clone()).map(|_| ())),
        ("getTlsConnection", 200) => Some(serde_json::from_value::<get_tls_connection::Answer200>(value.clone()).map(|_| ())),
        ("getTruststore", 200) => Some(serde_json::from_value::<get_truststore::Answer200>(value.clone()).map(|_| ())),
        ("addTrustAnchors", 200) => Some(serde_json::from_value::<add_trust_anchors::Answer200>(value.clone()).map(|_| ())),
        ("removeTrustAnchor", 200) => Some(serde_json::from_value::<remove_trust_anchor::Answer200>(value.clone()).map(|_| ())),
        ("getTokenLifetimes", 200) => Some(serde_json::from_value::<get_token_lifetimes::Answer200>(value.clone()).map(|_| ())),
        ("resetTokenLifetimes", 200) => Some(serde_json::from_value::<reset_token_lifetimes::Answer200>(value.clone()).map(|_| ())),
        ("setTokenLifetimes", 200) => Some(serde_json::from_value::<set_token_lifetimes::Answer200>(value.clone()).map(|_| ())),
        ("getIssued", 200) => Some(serde_json::from_value::<get_issued::Answer200>(value.clone()).map(|_| ())),
        ("getCredentialLineage", 200) => Some(serde_json::from_value::<get_credential_lineage::Answer200>(value.clone()).map(|_| ())),
        ("restoreToken", 200) => Some(serde_json::from_value::<restore_token::Answer200>(value.clone()).map(|_| ())),
        ("restoreIssuedArtifact", 200) => Some(serde_json::from_value::<restore_issued_artifact::Answer200>(value.clone()).map(|_| ())),
        ("restoreIssuedSet", 200) => Some(serde_json::from_value::<restore_issued_set::Answer200>(value.clone()).map(|_| ())),
        ("revokeToken", 200) => Some(serde_json::from_value::<revoke_token::Answer200>(value.clone()).map(|_| ())),
        ("revokeAllTokens", 200) => Some(serde_json::from_value::<revoke_all_tokens::Answer200>(value.clone()).map(|_| ())),
        ("revokeIssuedArtifact", 200) => Some(serde_json::from_value::<revoke_issued_artifact::Answer200>(value.clone()).map(|_| ())),
        ("revokeTokensByKind", 200) => Some(serde_json::from_value::<revoke_tokens_by_kind::Answer200>(value.clone()).map(|_| ())),
        ("revokeIssuedSet", 200) => Some(serde_json::from_value::<revoke_issued_set::Answer200>(value.clone()).map(|_| ())),
        ("revokeTokensBySubject", 200) => Some(serde_json::from_value::<revoke_tokens_by_subject::Answer200>(value.clone()).map(|_| ())),
        ("revokeTokensByUser", 200) => Some(serde_json::from_value::<revoke_tokens_by_user::Answer200>(value.clone()).map(|_| ())),
        ("getIssuedSet", 200) => Some(serde_json::from_value::<get_issued_set::Answer200>(value.clone()).map(|_| ())),
        ("getTotpSettings", 200) => Some(serde_json::from_value::<get_totp_settings::Answer200>(value.clone()).map(|_| ())),
        ("getUma", 200) => Some(serde_json::from_value::<get_uma::Answer200>(value.clone()).map(|_| ())),
        ("deleteUmaResource", 200) => Some(serde_json::from_value::<delete_uma_resource::Answer200>(value.clone()).map(|_| ())),
        ("disableUmaResourceServer", 200) => Some(serde_json::from_value::<disable_uma_resource_server::Answer200>(value.clone()).map(|_| ())),
        ("enableUmaResourceServer", 200) => Some(serde_json::from_value::<enable_uma_resource_server::Answer200>(value.clone()).map(|_| ())),
        ("getUmaMonitor", 200) => Some(serde_json::from_value::<get_uma_monitor::Answer200>(value.clone()).map(|_| ())),
        ("approveUmaRequest", 200) => Some(serde_json::from_value::<approve_uma_request::Answer200>(value.clone()).map(|_| ())),
        ("refuseUmaRequest", 200) => Some(serde_json::from_value::<refuse_uma_request::Answer200>(value.clone()).map(|_| ())),
        ("shareUmaResource", 200) => Some(serde_json::from_value::<share_uma_resource::Answer200>(value.clone()).map(|_| ())),
        ("unshareUmaResource", 200) => Some(serde_json::from_value::<unshare_uma_resource::Answer200>(value.clone()).map(|_| ())),
        ("revokeUmaRpt", 200) => Some(serde_json::from_value::<revoke_uma_rpt::Answer200>(value.clone()).map(|_| ())),
        ("setUmaOwnsResources", 200) => Some(serde_json::from_value::<set_uma_owns_resources::Answer200>(value.clone()).map(|_| ())),
        ("getUsedAssertions", 200) => Some(serde_json::from_value::<get_used_assertions::Answer200>(value.clone()).map(|_| ())),
        ("getUserInfoClaims", 200) => Some(serde_json::from_value::<get_user_info_claims::Answer200>(value.clone()).map(|_| ())),
        ("addUserInfoClaim", 200) => Some(serde_json::from_value::<add_user_info_claim::Answer200>(value.clone()).map(|_| ())),
        ("addUserInfoAttributeClaim", 200) => Some(serde_json::from_value::<add_user_info_attribute_claim::Answer200>(value.clone()).map(|_| ())),
        ("setUserInfoClaimAttributes", 200) => Some(serde_json::from_value::<set_user_info_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("selectAllUserInfoClaimAttributes", 200) => Some(serde_json::from_value::<select_all_user_info_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearUserInfoClaimAttributes", 200) => Some(serde_json::from_value::<clear_user_info_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearUserInfoClaims", 200) => Some(serde_json::from_value::<clear_user_info_claims::Answer200>(value.clone()).map(|_| ())),
        ("removeUserInfoClaim", 200) => Some(serde_json::from_value::<remove_user_info_claim::Answer200>(value.clone()).map(|_| ())),
        ("replaceUserInfoClaims", 200) => Some(serde_json::from_value::<replace_user_info_claims::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
