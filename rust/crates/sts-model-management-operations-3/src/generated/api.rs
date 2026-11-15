// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// Where this realm's audit events are delivered (#641)
pub mod get_audit_export {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/audit-export";
    pub const OPERATION_ID: &str = "getAuditExport";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Job {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Stats {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivered: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub awaiting: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retrying: Option<f64>,
        #[serde(rename = "permanentlyFailed", default, skip_serializing_if = "Option::is_none")]
        pub permanently_failed: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dropped: Option<f64>,
        #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
        pub latency_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub availability: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generated: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "thisProcess", default, skip_serializing_if = "Option::is_none")]
        pub this_process: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<Answer200Job>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destinations: Option<Vec<sts_model_management_components_4::WithIdNameType3>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stats: Option<Answer200Stats>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
    }
}

/// Add an audit export destination
pub mod add_audit_export_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/audit-export/add";
    pub const OPERATION_ID: &str = "addAuditExportDestination";

    /// syslog, file, webhook, splunk, or logrhythm. LogRhythm is the syslog
    /// adapter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "syslog")]
        Syslog,
        #[serde(rename = "file")]
        File,
        #[serde(rename = "webhook")]
        Webhook,
        #[serde(rename = "splunk")]
        Splunk,
        #[serde(rename = "logrhythm")]
        Logrhythm,
    }

    /// syslog and logrhythm. TCP when omitted. UDP is fire-and-forget.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTransport {
        #[serde(rename = "tcp")]
        Tcp,
        #[serde(rename = "udp")]
        Udp,
        #[serde(rename = "tls")]
        Tls,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination id. A letter or a digit, then lower-case letters, digits
        /// and hyphens. It does not change.
        pub id: String,
        /// What to call it on the page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// syslog, file, webhook, splunk, or logrhythm. LogRhythm is the syslog
        /// adapter.
        #[serde(rename = "type")]
        pub type_: BodyType,
        /// Whether the job delivers to it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// More detail names to remove, separated by commas.
        #[serde(rename = "excludeAttributes", default, skip_serializing_if = "Option::is_none")]
        pub exclude_attributes: Option<String>,
        /// syslog and logrhythm: the host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        /// syslog and logrhythm: the port. 0 or omitted is 6514 for TLS and 514
        /// otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        /// syslog and logrhythm. TCP when omitted. UDP is fire-and-forget.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport: Option<BodyTransport>,
        /// syslog and logrhythm. 16 is local0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facility: Option<i64>,
        /// syslog and logrhythm: the APP-NAME. iya-sts when empty.
        #[serde(rename = "appName", default, skip_serializing_if = "Option::is_none")]
        pub app_name: Option<String>,
        /// file: an absolute path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// file: three octal digits, such as 640.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        /// file: rotate at this size. 0 is off.
        #[serde(rename = "rotateBytes", default, skip_serializing_if = "Option::is_none")]
        pub rotate_bytes: Option<i64>,
        /// webhook or Splunk HEC: an https URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// webhook: one line with {timestamp} and the other placeholders. Empty
        /// sends the canonical event as JSON.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub template: Option<String>,
        /// webhook: the content type. Empty is JSON, or text when a template is
        /// set.
        #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none")]
        pub content_type: Option<String>,
        /// webhook: plain headers, one "Name: value" a line. Sent back on a change.
        /// Empty replaces them. A name that looks like a credential is sealed
        /// instead.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub headers: Option<String>,
        /// webhook: sealed headers, one "Name: value" a line. Never returned. Empty
        /// keeps every one. A blank value keeps that one name.
        #[serde(rename = "secretHeaders", default, skip_serializing_if = "Option::is_none")]
        pub secret_headers: Option<String>,
        /// Splunk HEC: the collector token. Never returned. Empty on a change keeps
        /// it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        /// Splunk HEC: the index. Empty uses the token's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub index: Option<String>,
        /// Splunk HEC: the sourcetype. iya:audit when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sourcetype: Option<String>,
        /// Splunk HEC: the source. iya-sts when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        /// Splunk HEC: wait for the indexer ack before the cursor moves. One event
        /// is in flight.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ack: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors188;
}

/// Disable an audit export destination
pub mod disable_audit_export_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/audit-export/disable";
    pub const OPERATION_ID: &str = "disableAuditExportDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination id. A letter or a digit, then lower-case letters, digits
        /// and hyphens. It does not change.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors188;
}

/// Enable an audit export destination
pub mod enable_audit_export_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/audit-export/enable";
    pub const OPERATION_ID: &str = "enableAuditExportDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination id. A letter or a digit, then lower-case letters, digits
        /// and hyphens. It does not change.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors188;
}

/// Remove an audit export destination
pub mod remove_audit_export_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/audit-export/remove";
    pub const OPERATION_ID: &str = "removeAuditExportDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination id. A letter or a digit, then lower-case letters, digits
        /// and hyphens. It does not change.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors188;
}

/// Send a synthetic audit export event
pub mod test_audit_export_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/audit-export/test";
    pub const OPERATION_ID: &str = "testAuditExportDestination";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination id. A letter or a digit, then lower-case letters, digits
        /// and hyphens. It does not change.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors188;
}

/// Change an audit export destination
pub mod update_audit_export_destination {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/audit-export/update";
    pub const OPERATION_ID: &str = "updateAuditExportDestination";

    /// syslog, file, webhook, splunk, or logrhythm. LogRhythm is the syslog
    /// adapter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "syslog")]
        Syslog,
        #[serde(rename = "file")]
        File,
        #[serde(rename = "webhook")]
        Webhook,
        #[serde(rename = "splunk")]
        Splunk,
        #[serde(rename = "logrhythm")]
        Logrhythm,
    }

    /// syslog and logrhythm. TCP when omitted. UDP is fire-and-forget.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTransport {
        #[serde(rename = "tcp")]
        Tcp,
        #[serde(rename = "udp")]
        Udp,
        #[serde(rename = "tls")]
        Tls,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The destination id. A letter or a digit, then lower-case letters, digits
        /// and hyphens. It does not change.
        pub id: String,
        /// What to call it on the page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// syslog, file, webhook, splunk, or logrhythm. LogRhythm is the syslog
        /// adapter.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// Whether the job delivers to it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// More detail names to remove, separated by commas.
        #[serde(rename = "excludeAttributes", default, skip_serializing_if = "Option::is_none")]
        pub exclude_attributes: Option<String>,
        /// syslog and logrhythm: the host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        /// syslog and logrhythm: the port. 0 or omitted is 6514 for TLS and 514
        /// otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        /// syslog and logrhythm. TCP when omitted. UDP is fire-and-forget.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport: Option<BodyTransport>,
        /// syslog and logrhythm. 16 is local0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub facility: Option<i64>,
        /// syslog and logrhythm: the APP-NAME. iya-sts when empty.
        #[serde(rename = "appName", default, skip_serializing_if = "Option::is_none")]
        pub app_name: Option<String>,
        /// file: an absolute path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        /// file: three octal digits, such as 640.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        /// file: rotate at this size. 0 is off.
        #[serde(rename = "rotateBytes", default, skip_serializing_if = "Option::is_none")]
        pub rotate_bytes: Option<i64>,
        /// webhook or Splunk HEC: an https URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// webhook: one line with {timestamp} and the other placeholders. Empty
        /// sends the canonical event as JSON.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub template: Option<String>,
        /// webhook: the content type. Empty is JSON, or text when a template is
        /// set.
        #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none")]
        pub content_type: Option<String>,
        /// webhook: plain headers, one "Name: value" a line. Sent back on a change.
        /// Empty replaces them. A name that looks like a credential is sealed
        /// instead.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub headers: Option<String>,
        /// webhook: sealed headers, one "Name: value" a line. Never returned. Empty
        /// keeps every one. A blank value keeps that one name.
        #[serde(rename = "secretHeaders", default, skip_serializing_if = "Option::is_none")]
        pub secret_headers: Option<String>,
        /// Splunk HEC: the collector token. Never returned. Empty on a change keeps
        /// it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        /// Splunk HEC: the index. Empty uses the token's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub index: Option<String>,
        /// Splunk HEC: the sourcetype. iya:audit when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sourcetype: Option<String>,
        /// Splunk HEC: the source. iya-sts when empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        /// Splunk HEC: wait for the indexer ack before the cursor moves. One event
        /// is in flight.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ack: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors188;
}

/// Every outbound delivery on the shared queue, by kind
pub mod get_outbound_deliveries {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/deliveries";
    pub const OPERATION_ID: &str = "getOutboundDeliveries";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "backchannelLogoutPage", default, skip_serializing_if = "Option::is_none")]
        pub backchannel_logout_page: Option<i64>,
        #[serde(rename = "cibaPage", default, skip_serializing_if = "Option::is_none")]
        pub ciba_page: Option<i64>,
        #[serde(rename = "cellOpsPage", default, skip_serializing_if = "Option::is_none")]
        pub cell_ops_page: Option<i64>,
        #[serde(rename = "providerCommandsPage", default, skip_serializing_if = "Option::is_none")]
        pub provider_commands_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KindsItemCounts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sent: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dead: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KindsItemRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub uri: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attempts: Option<f64>,
        #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
        pub in_flight: Option<sts_model_base::unions::BoolOrNumber>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub status: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
        #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub error_code: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
        pub queued_at: Option<sts_model_base::unions::NumberOrString>,
        #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub next_attempt_at: Option<sts_model_base::unions::NumberOrString>,
        #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub last_attempt_at: Option<sts_model_base::unions::NumberOrString>,
        #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
        pub finished_at: Option<sts_model_base::unions::NumberOrString>,
        #[serde(rename = "authReqId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub auth_req_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub mode: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub session_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub iss: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sub: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub sid: Option<Option<String>>,
        #[serde(rename = "sessionRequired", default, skip_serializing_if = "Option::is_none")]
        pub session_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub via: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub trigger: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub encrypted: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub command: Option<Option<String>>,
        #[serde(rename = "accountState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub account_state: Option<Option<String>>,
        #[serde(rename = "awaitingCallback", default, skip_serializing_if = "Option::is_none")]
        pub awaiting_callback: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cell: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub op: Option<Option<String>>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
        pub updated_at: Option<f64>,
        #[serde(rename = "fenceAt", default, skip_serializing_if = "Option::is_none")]
        pub fence_at: Option<f64>,
        #[serde(rename = "tokenDigest", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub token_digest: Option<Option<String>>,
        #[serde(rename = "bodyDigest", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub body_digest: Option<Option<String>>,
        /// What an inter-cell operation carries, which is that operation's own
        /// request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub body: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KindsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200KindsItemCounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200KindsItemRowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<Answer200KindsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub states: Option<Vec<String>>,
    }
}

/// Retry a dead letter of any kind
pub mod retry_outbound_delivery {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/deliveries/retry";
    pub const OPERATION_ID: &str = "retryOutboundDelivery";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "backchannel-logout")]
        BackchannelLogout,
        #[serde(rename = "ciba")]
        Ciba,
        #[serde(rename = "provider-commands")]
        ProviderCommands,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub kind: BodyKind,
        pub delivery: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors193;
}

/// Every federation relationship, in either direction
pub mod get_federation_relationships {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/federation";
    pub const OPERATION_ID: &str = "getFederationRelationships";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryRole {
        #[serde(rename = "service-provider")]
        ServiceProvider,
        #[serde(rename = "identity-provider")]
        IdentityProvider,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryCategory {
        #[serde(rename = "enterprise")]
        Enterprise,
        #[serde(rename = "consumer")]
        Consumer,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationship: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<QueryRole>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<QueryCategory>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "linksPage", default, skip_serializing_if = "Option::is_none")]
        pub links_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub q: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub role: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub category: Option<Option<String>>,
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
    pub struct Answer200Paths {
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
    pub struct Answer200ConsumerProvidersCatalogueItem {
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
    pub struct Answer200ConsumerProviders {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalogue: Option<Vec<Answer200ConsumerProvidersCatalogueItem>>,
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
    pub struct Answer200ProviderV1 {
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
    pub enum Answer200Provider {
        V1(Answer200ProviderV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Endpoints {
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
    pub struct Answer200Fields {
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
    pub struct Answer200UnmappedAttributesItem {
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
    pub struct Answer200SignalsCredential {
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
    pub struct Answer200SignalsCounts {
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
    pub struct Answer200Signals {
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
        pub credential: Option<Answer200SignalsCredential>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ready: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub config: Option<sts_model_management_components_1::ConfigValue>,
        #[serde(rename = "discoveryUrl", default, skip_serializing_if = "Option::is_none")]
        pub discovery_url: Option<String>,
        #[serde(rename = "discoveredAt", default, skip_serializing_if = "Option::is_none")]
        pub discovered_at: Option<String>,
        #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
        pub stream_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stream: Option<sts_model_management_components_3::StreamValue>,
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
        pub counts: Option<Answer200SignalsCounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub blocks: Option<sts_model_management_components_4::WithRelationshipUsernameAt>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OutboundSignalsStreamsItem {
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
    pub struct Answer200OutboundSignals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub streams: Option<Vec<Answer200OutboundSignalsStreamsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EncryptionPolicy {
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
    pub struct Answer200EncryptionKeysItem {
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
    pub struct Answer200Encryption {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Answer200EncryptionPolicy>,
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
        pub jwk: Option<sts_model_management_components_2::JwkValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200EncryptionKeysItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientCertificate {
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
    pub struct Answer200LinksItem {
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
    pub struct Answer200SignOut {
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
    pub struct Answer200 {
        #[serde(rename = "relationshipCount", default, skip_serializing_if = "Option::is_none")]
        pub relationship_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ready: Option<sts_model_base::unions::BoolOrInteger>,
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
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub container: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<Answer200RolesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<Answer200ProtocolsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<Answer200Paths>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "roleCounts", default, skip_serializing_if = "Option::is_none")]
        pub role_counts: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "categoryCounts", default, skip_serializing_if = "Option::is_none")]
        pub category_counts: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "consumerProviders", default, skip_serializing_if = "Option::is_none")]
        pub consumer_providers: Option<Answer200ConsumerProviders>,
        #[serde(rename = "enabledNotConfigured", default, skip_serializing_if = "Option::is_none")]
        pub enabled_not_configured: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentications: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationships: Option<Vec<Answer200RelationshipsItem>>,
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
        pub provider: Option<Option<Answer200Provider>>,
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
        pub endpoints: Option<Answer200Endpoints>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Answer200Fields>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub editable: Option<sts_model_management_components_4::WithDescriptionAdditionalPropertiesProperties>,
        #[serde(rename = "unmappedAttributes", default, skip_serializing_if = "Option::is_none")]
        pub unmapped_attributes: Option<Vec<Answer200UnmappedAttributesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signals: Option<Answer200Signals>,
        #[serde(rename = "signalArrivals", default, skip_serializing_if = "Option::is_none")]
        pub signal_arrivals: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesKty>,
        #[serde(rename = "outboundSignals", default, skip_serializing_if = "Option::is_none")]
        pub outbound_signals: Option<Answer200OutboundSignals>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub encryption: Option<Answer200Encryption>,
        #[serde(rename = "clientCertificate", default, skip_serializing_if = "Option::is_none")]
        pub client_certificate: Option<Answer200ClientCertificate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<Answer200LinksItem>>,
        #[serde(rename = "linksPaging", default, skip_serializing_if = "Option::is_none")]
        pub links_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "setFields", default, skip_serializing_if = "Option::is_none")]
        pub set_fields: Option<sts_model_management_components_4::WithDescriptionAdditionalPropertiesProperties>,
        #[serde(rename = "multiFields", default, skip_serializing_if = "Option::is_none")]
        pub multi_fields: Option<sts_model_management_components_4::WithDescriptionAdditionalPropertiesProperties>,
        #[serde(rename = "signalSetFields", default, skip_serializing_if = "Option::is_none")]
        pub signal_set_fields: Option<sts_model_management_components_4::WithDescriptionAdditionalPropertiesProperties>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<sts_model_management_components_4::WithDescriptionAdditionalPropertiesProperties>,
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
        pub sign_out: Option<Answer200SignOut>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Add a value to a multi-valued field
pub mod add_federation_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/add-value";
    pub const OPERATION_ID: &str = "addFederationValue";

    /// Which list.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyField {
        #[serde(rename = "description")]
        Description,
        #[serde(rename = "fedAllowedTenants")]
        FedAllowedTenants,
        #[serde(rename = "fedAuthorizeParams")]
        FedAuthorizeParams,
        #[serde(rename = "fedAttributeMap")]
        FedAttributeMap,
        #[serde(rename = "fedSubjectGroup")]
        FedSubjectGroup,
        #[serde(rename = "fedSubjectDomain")]
        FedSubjectDomain,
        #[serde(rename = "fedHomeRealmDomain")]
        FedHomeRealmDomain,
        #[serde(rename = "fedSignalsEvents")]
        FedSignalsEvents,
        #[serde(rename = "fedRelease")]
        FedRelease,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
        /// Which list.
        pub field: BodyField,
        /// The value to add.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Check an OpenID Connect partner's configuration
pub mod check_federation_partner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/check-partner";
    pub const OPERATION_ID: &str = "checkFederationPartner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors80;
}

/// Register a federation relationship
pub mod create_federation_relationship {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/create";
    pub const OPERATION_ID: &str = "createFederationRelationship";

    /// Which end THIS SERVICE is. `service-provider` means a foreign identity
    /// provider authenticates the person and this service consumes what it issues.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyRole {
        #[serde(rename = "service-provider")]
        ServiceProvider,
        #[serde(rename = "identity-provider")]
        IdentityProvider,
    }

    /// The protocol the relationship runs in. `ssf` (#374) is a partner that signs
    /// nobody in and only sends Shared Signals; it takes the service-provider role.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProtocol {
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "saml11")]
        Saml11,
        #[serde(rename = "wsfed")]
        Wsfed,
        #[serde(rename = "oidc")]
        Oidc,
        #[serde(rename = "oauth2")]
        Oauth2,
        #[serde(rename = "ssf")]
        Ssf,
    }

    /// A CONSUMER OR SOCIAL PROVIDER (#565): the profile the relationship is made
    /// from. Its endpoints, issuer, scope and token authentication are written onto
    /// the relationship, `role` must be `service-provider` and `protocol` the
    /// profile's (both are in `consumerProviders` on `GET /admin-api/federation`),
    /// and the realm must have `federation.consumerProviders` on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyProvider {
        #[serde(rename = "google")]
        Google,
        #[serde(rename = "discord")]
        Discord,
        #[serde(rename = "github")]
        Github,
        #[serde(rename = "microsoft")]
        Microsoft,
        #[serde(rename = "microsoft-any")]
        MicrosoftAny,
        #[serde(rename = "linkedin")]
        Linkedin,
        #[serde(rename = "yahoo")]
        Yahoo,
        #[serde(rename = "slack")]
        Slack,
        #[serde(rename = "twitch")]
        Twitch,
        #[serde(rename = "salesforce")]
        Salesforce,
        #[serde(rename = "facebook")]
        Facebook,
        #[serde(rename = "amazon")]
        Amazon,
        #[serde(rename = "spotify")]
        Spotify,
        #[serde(rename = "x")]
        X,
        #[serde(rename = "tiktok")]
        Tiktok,
        #[serde(rename = "apple")]
        Apple,
        #[serde(rename = "gitlab")]
        Gitlab,
        #[serde(rename = "gitlab-self-managed")]
        GitlabSelfManaged,
        #[serde(rename = "bitbucket")]
        Bitbucket,
        #[serde(rename = "patreon")]
        Patreon,
        #[serde(rename = "roblox")]
        Roblox,
        #[serde(rename = "battlenet")]
        Battlenet,
        #[serde(rename = "epic")]
        Epic,
        #[serde(rename = "paypal")]
        Paypal,
        #[serde(rename = "dropbox")]
        Dropbox,
        #[serde(rename = "box")]
        Box,
        #[serde(rename = "steam")]
        Steam,
        #[serde(rename = "codeberg")]
        Codeberg,
        #[serde(rename = "gitea")]
        Gitea,
        #[serde(rename = "huggingface")]
        Huggingface,
        #[serde(rename = "asana")]
        Asana,
        #[serde(rename = "atlassian")]
        Atlassian,
        #[serde(rename = "replit")]
        Replit,
        #[serde(rename = "mastodon")]
        Mastodon,
        #[serde(rename = "sourceforge")]
        Sourceforge,
        #[serde(rename = "stackoverflow")]
        Stackoverflow,
        #[serde(rename = "oschina")]
        Oschina,
        #[serde(rename = "discourse")]
        Discourse,
        #[serde(rename = "bluesky")]
        Bluesky,
        #[serde(rename = "generic-oidc")]
        GenericOidc,
        #[serde(rename = "generic-oauth2")]
        GenericOauth2,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The key, the RDN and a URL segment. It has to start with a letter or a
        /// digit and hold only letters, digits, dot, dash and underscore, up to 63
        /// characters.
        pub id: String,
        /// Which end THIS SERVICE is. `service-provider` means a foreign identity
        /// provider authenticates the person and this service consumes what it
        /// issues.
        pub role: BodyRole,
        /// The protocol the relationship runs in. `ssf` (#374) is a partner that
        /// signs nobody in and only sends Shared Signals; it takes the
        /// service-provider role.
        pub protocol: BodyProtocol,
        /// What to call the partner on a page. The id is the name when this is
        /// omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The partner's own identifier — a SAML entityID, an OpenID Connect
        /// issuer, a WS-Federation wtrealm. On a service-provider-side relationship
        /// it is CHECKED: an assertion whose issuer is not this string is refused
        /// even when the signature verifies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer: Option<String>,
        /// On an identity-provider-side relationship only: the identifier of the
        /// partner's entry in `ou=applications`. Its entityID, redirect URIs and
        /// certificate stay THERE, where every protocol module reads them — this
        /// register holds a pointer and not a copy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        /// A CONSUMER OR SOCIAL PROVIDER (#565): the profile the relationship is
        /// made from. Its endpoints, issuer, scope and token authentication are
        /// written onto the relationship, `role` must be `service-provider` and
        /// `protocol` the profile's (both are in `consumerProviders` on `GET
        /// /admin-api/federation`), and the realm must have
        /// `federation.consumerProviders` on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<BodyProvider>,
        /// With `provider`: this service's client_id at the provider, set as
        /// `fedClientId` in the same act.
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        /// With `provider`: this service's secret at the provider, set as
        /// `fedClientSecret` in the same act and sealed as that field always is.
        /// Never echoed.
        #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
        pub client_secret: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Delete a relationship
pub mod delete_federation_relationship {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/delete";
    pub const OPERATION_ID: &str = "deleteFederationRelationship";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
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

/// Turn a relationship off
pub mod disable_federation_relationship {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/disable";
    pub const OPERATION_ID: &str = "disableFederationRelationship";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Turn a relationship on
pub mod enable_federation_relationship {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/enable";
    pub const OPERATION_ID: &str = "enableFederationRelationship";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Register this service at an OpenID Connect partner
pub mod register_at_federation_partner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/register-partner";
    pub const OPERATION_ID: &str = "registerAtFederationPartner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
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
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
    }
}

/// Remove one value from a multi-valued field
pub mod remove_federation_value {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/remove-value";
    pub const OPERATION_ID: &str = "removeFederationValue";

    /// Which list.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyField {
        #[serde(rename = "description")]
        Description,
        #[serde(rename = "fedAllowedTenants")]
        FedAllowedTenants,
        #[serde(rename = "fedAuthorizeParams")]
        FedAuthorizeParams,
        #[serde(rename = "fedAttributeMap")]
        FedAttributeMap,
        #[serde(rename = "fedSubjectGroup")]
        FedSubjectGroup,
        #[serde(rename = "fedSubjectDomain")]
        FedSubjectDomain,
        #[serde(rename = "fedHomeRealmDomain")]
        FedHomeRealmDomain,
        #[serde(rename = "fedSignalsEvents")]
        FedSignalsEvents,
        #[serde(rename = "fedRelease")]
        FedRelease,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
        /// Which list.
        pub field: BodyField,
        /// The value to remove, exactly as it stands.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Rotate a relationship's encryption key
pub mod rotate_federation_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/rotate-key";
    pub const OPERATION_ID: &str = "rotateFederationKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Set one single-valued field on a relationship
pub mod set_federation_field {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/set";
    pub const OPERATION_ID: &str = "setFederationField";

    /// The attribute name, e.g. `fedSsoUrl`, `fedSigningCertificate`,
    /// `fedClientId`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyField {
        #[serde(rename = "fedName")]
        FedName,
        #[serde(rename = "fedPeer")]
        FedPeer,
        #[serde(rename = "fedLocalEntityId")]
        FedLocalEntityId,
        #[serde(rename = "fedEnabled")]
        FedEnabled,
        #[serde(rename = "fedSsoUrl")]
        FedSsoUrl,
        #[serde(rename = "fedTokenUrl")]
        FedTokenUrl,
        #[serde(rename = "fedUserinfoUrl")]
        FedUserinfoUrl,
        #[serde(rename = "fedJwksUri")]
        FedJwksUri,
        #[serde(rename = "fedEmailsUrl")]
        FedEmailsUrl,
        #[serde(rename = "fedJwks")]
        FedJwks,
        #[serde(rename = "fedTrustAnchor")]
        FedTrustAnchor,
        #[serde(rename = "fedSigningCertificate")]
        FedSigningCertificate,
        #[serde(rename = "fedClientId")]
        FedClientId,
        #[serde(rename = "fedClientSecret")]
        FedClientSecret,
        #[serde(rename = "fedResponseMode")]
        FedResponseMode,
        #[serde(rename = "fedTeamId")]
        FedTeamId,
        #[serde(rename = "fedKeyId")]
        FedKeyId,
        #[serde(rename = "fedClientSigningKey")]
        FedClientSigningKey,
        #[serde(rename = "fedTokenAuth")]
        FedTokenAuth,
        #[serde(rename = "fedScope")]
        FedScope,
        #[serde(rename = "fedResponseType")]
        FedResponseType,
        #[serde(rename = "fedIdTokenSignedResponseAlg")]
        FedIdTokenSignedResponseAlg,
        #[serde(rename = "fedUserinfoSignedResponseAlg")]
        FedUserinfoSignedResponseAlg,
        #[serde(rename = "fedUserinfo")]
        FedUserinfo,
        #[serde(rename = "fedRefreshTokens")]
        FedRefreshTokens,
        #[serde(rename = "fedRefreshEverySeconds")]
        FedRefreshEverySeconds,
        #[serde(rename = "fedRegister")]
        FedRegister,
        #[serde(rename = "fedRegisteredIssuer")]
        FedRegisteredIssuer,
        #[serde(rename = "fedRequestObject")]
        FedRequestObject,
        #[serde(rename = "fedRequestObjectSigningAlg")]
        FedRequestObjectSigningAlg,
        #[serde(rename = "fedWebFinger")]
        FedWebFinger,
        #[serde(rename = "fedDiscovery")]
        FedDiscovery,
        #[serde(rename = "fedFapi")]
        FedFapi,
        #[serde(rename = "fedInitiateLogin")]
        FedInitiateLogin,
        #[serde(rename = "fedBinding")]
        FedBinding,
        #[serde(rename = "fedSignRequest")]
        FedSignRequest,
        #[serde(rename = "fedUsernameSource")]
        FedUsernameSource,
        #[serde(rename = "fedSubjectClaim")]
        FedSubjectClaim,
        #[serde(rename = "fedAutocreateUsers")]
        FedAutocreateUsers,
        #[serde(rename = "fedUpdateUserAttributes")]
        FedUpdateUserAttributes,
        #[serde(rename = "fedProvisionGroups")]
        FedProvisionGroups,
        #[serde(rename = "fedProvisionCap")]
        FedProvisionCap,
        #[serde(rename = "fedProvisionIdleMinutes")]
        FedProvisionIdleMinutes,
        #[serde(rename = "fedSubjectPolicy")]
        FedSubjectPolicy,
        #[serde(rename = "fedSubjectPattern")]
        FedSubjectPattern,
        #[serde(rename = "fedMayAssertAdministrators")]
        FedMayAssertAdministrators,
        #[serde(rename = "fedSignalEmailMatch")]
        FedSignalEmailMatch,
        #[serde(rename = "fedSignalsEnabled")]
        FedSignalsEnabled,
        #[serde(rename = "fedSignalsIssuer")]
        FedSignalsIssuer,
        #[serde(rename = "fedSignalsDelivery")]
        FedSignalsDelivery,
        #[serde(rename = "fedSignalsTokenUrl")]
        FedSignalsTokenUrl,
        #[serde(rename = "fedSignalsClientId")]
        FedSignalsClientId,
        #[serde(rename = "fedSignalsClientSecret")]
        FedSignalsClientSecret,
        #[serde(rename = "fedSignalsScope")]
        FedSignalsScope,
        #[serde(rename = "fedSignalsBearer")]
        FedSignalsBearer,
        #[serde(rename = "fedSloUrl")]
        FedSloUrl,
        #[serde(rename = "fedSloBinding")]
        FedSloBinding,
        #[serde(rename = "fedEndSessionUrl")]
        FedEndSessionUrl,
        #[serde(rename = "fedAcceptSignout")]
        FedAcceptSignout,
        #[serde(rename = "fedRequireSignedLogout")]
        FedRequireSignedLogout,
        #[serde(rename = "fedEncryptionKeyType")]
        FedEncryptionKeyType,
        #[serde(rename = "fedKeyManagementAlgorithm")]
        FedKeyManagementAlgorithm,
        #[serde(rename = "fedContentEncryptionAlgorithm")]
        FedContentEncryptionAlgorithm,
        #[serde(rename = "fedAllowUnencrypted")]
        FedAllowUnencrypted,
        #[serde(rename = "fedAllowUnsolicited")]
        FedAllowUnsolicited,
        #[serde(rename = "fedApplication")]
        FedApplication,
        #[serde(rename = "fedAuthnMechanism")]
        FedAuthnMechanism,
        #[serde(rename = "fedAuthnRelationship")]
        FedAuthnRelationship,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
        /// The attribute name, e.g. `fedSsoUrl`, `fedSigningCertificate`,
        /// `fedClientId`.
        pub field: BodyField,
        /// The new value. An empty string clears it. `fedSigningCertificate` is
        /// normalised — PEM armour and whitespace are stripped, because what the
        /// schema holds is the base64 DER a ds:X509Certificate carries.
        pub value: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors79;
}

/// Add a subject to the stream at the partner
pub mod add_federation_signals_subject {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-add-subject";
    pub const OPERATION_ID: &str = "addFederationSignalsSubject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
        pub subject: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Create this realm's stream at the partner
pub mod create_federation_signals_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-create-stream";
    pub const OPERATION_ID: &str = "createFederationSignalsStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Delete the stream at the partner
pub mod delete_federation_signals_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-delete-stream";
    pub const OPERATION_ID: &str = "deleteFederationSignalsStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Discover the partner's Shared Signals configuration
pub mod discover_federation_signals {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-discover";
    pub const OPERATION_ID: &str = "discoverFederationSignals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Poll the partner now
pub mod poll_federation_signals {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-poll-now";
    pub const OPERATION_ID: &str = "pollFederationSignals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Read the stream's status from the partner
pub mod read_federation_signals_status {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-read-status";
    pub const OPERATION_ID: &str = "readFederationSignalsStatus";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Read the stream's configuration from the partner
pub mod read_federation_signals_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-read-stream";
    pub const OPERATION_ID: &str = "readFederationSignalsStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Remove a subject from the stream at the partner
pub mod remove_federation_signals_subject {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-remove-subject";
    pub const OPERATION_ID: &str = "removeFederationSignalsSubject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
        pub subject: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Replace the stream's configuration at the partner
pub mod replace_federation_signals_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-replace-stream";
    pub const OPERATION_ID: &str = "replaceFederationSignalsStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Enable, pause or disable the stream at the partner
pub mod set_federation_signals_status {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-set-status";
    pub const OPERATION_ID: &str = "setFederationSignalsStatus";

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
        /// The relationship.
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Lift a partner's block on a person's sign-ins
pub mod unblock_federation_signals {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-unblock";
    pub const OPERATION_ID: &str = "unblockFederationSignals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
        /// The person.
        pub user: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Send fedSignalsEvents to the stream
pub mod update_federation_signals_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-update-stream";
    pub const OPERATION_ID: &str = "updateFederationSignalsStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// Ask the partner for a verification event
pub mod verify_federation_signals_stream {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/federation/signals-verify";
    pub const OPERATION_ID: &str = "verifyFederationSignalsStream";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The relationship.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors81;
}

/// The GNAP authorization server: endpoints, capabilities, grants, resource
/// sets, settings
pub mod get_gnap {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/gnap";
    pub const OPERATION_ID: &str = "getGnap";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(rename = "resourcesPage", default, skip_serializing_if = "Option::is_none")]
        pub resources_page: Option<i64>,
        #[serde(rename = "serversPage", default, skip_serializing_if = "Option::is_none")]
        pub servers_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::GnapServer;
}

/// Delete a registered resource set (RFC 9767 section 3.4)
pub mod delete_gnap_resource_set {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/gnap/delete-resource-set";
    pub const OPERATION_ID: &str = "deleteGnapResourceSet";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The resource reference, from GET /admin-api/gnap.
        pub reference: String,
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
        pub reference: Option<String>,
    }
}

/// Every application that uses GNAP, and what each has done
pub mod get_gnap_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/gnap/monitor";
    pub const OPERATION_ID: &str = "getGnapMonitor";

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

    pub type Answer200 = sts_model_management_components_2::GnapMonitor;
}

/// Revoke a GNAP grant, as its client could (RFC 9635 section 5.4)
pub mod revoke_gnap_grant {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/gnap/revoke-grant";
    pub const OPERATION_ID: &str = "revokeGnapGrant";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The grant identifier, from GET /admin-api/gnap or the person's
        /// `gnapGrants`.
        pub grant: String,
        /// The person whose grant it must be (optional). A grant whose resource
        /// owner is somebody else is refused and nothing changes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors106;
}

/// Every group in the embedded LDAP directory, or one in full
pub mod get_groups {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/groups";
    pub const OPERATION_ID: &str = "getGroups";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exclude: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "membersPage", default, skip_serializing_if = "Option::is_none")]
        pub members_page: Option<i64>,
        #[serde(rename = "claimedPage", default, skip_serializing_if = "Option::is_none")]
        pub claimed_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200V3 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200V4GroupsItem {
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
    pub struct Answer200V4AdminGroups {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub read: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub write: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200V4 {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<()>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<Answer200V4GroupsItem>>,
        #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
        pub group_count: Option<f64>,
        #[serde(rename = "entryDn", default, skip_serializing_if = "Option::is_none")]
        pub entry_dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub wanted: Option<String>,
        #[serde(rename = "adminGroups", default, skip_serializing_if = "Option::is_none")]
        pub admin_groups: Option<Answer200V4AdminGroups>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200V5GroupOwnersItem {
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
    pub struct Answer200V5Group {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<sts_model_management_components_4::WithDnOriginCreatedAt>,
        #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
        pub member_count: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<Vec<Answer200V5GroupOwnersItem>>,
        #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
        pub max_owners: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200V5 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<Answer200V5Group>,
        #[serde(rename = "membersPaging", default, skip_serializing_if = "Option::is_none")]
        pub members_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200 {
        GroupList(sts_model_management_components_2::GroupList),
        GroupDetail(sts_model_management_components_2::GroupDetail),
        V3(Answer200V3),
        V4(Answer200V4),
        V5(Answer200V5),
    }
}

/// Put somebody in a group that already exists
pub mod add_group_member {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/groups/add-member";
    pub const OPERATION_ID: &str = "addGroupMember";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The group's `cn` or its whole DN.
        pub group: String,
        /// A user name, or the DN of any entry.
        pub member: String,
        /// Accepted for `member`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// Accepted for `member`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors57;
}

/// Add one owner to a group
pub mod add_group_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/groups/add-owner";
    pub const OPERATION_ID: &str = "addGroupOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The group's `cn`, DN or SCIM id.
        pub group: String,
        /// The person or group to add.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors60;
}

/// Put a group in the directory
pub mod create_group {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/groups/create";
    pub const OPERATION_ID: &str = "createGroup";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyMembers {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `cn`. Not a DN — this puts it under `ou=groups` in the realm the
        /// call is made in.
        pub group: String,
        /// Accepted for `group`, spelt the way SCIM spells it.
        #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// What the entry's `description` says about why it exists. Defaults to a
        /// sentence saying it was created by hand rather than by a directory
        /// client.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        /// Who is in it, as an array of user names or DNs — a group can hold
        /// another group, and no user name names one. A form sends one string,
        /// split on newlines and commas. A bare name resolves to that person's OWN
        /// entry wherever it is, because somebody seeded by a client certificate is
        /// at `cn=<name>,ou=users` and a value written in the `uid=` form would
        /// dangle beside the entry it meant to name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<BodyMembers>,
        /// The group's own email address, its `mail` attribute (#989): where a
        /// report definition shared with the group sends its result notices. One
        /// address, or omitted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors56;
}

/// Take one owner off a group
pub mod remove_group_owner {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/groups/remove-owner";
    pub const OPERATION_ID: &str = "removeGroupOwner";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The group's `cn`, DN or SCIM id.
        pub group: String,
        /// The owner's DN.
        pub owner: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors60;
}

/// Set or clear a group's email address
pub mod set_group_mail {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/groups/set-mail";
    pub const OPERATION_ID: &str = "setGroupMail";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The group's `cn` or its whole DN.
        pub group: String,
        /// The address, or empty to remove it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors58;
}

/// Set or clear the named policy a group names of one kind
pub mod set_group_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/groups/set-policy";
    pub const OPERATION_ID: &str = "setGroupPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The group's `cn` or its whole DN.
        pub group: String,
        /// The reference attribute, as `policyReferences` lists it.
        pub attribute: String,
        /// `default`, a named policy of the kind, or empty to remove it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors59;
}

/// The KDC's own settings
pub mod get_kerberos_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/kerberos";
    pub const OPERATION_ID: &str = "getKerberosSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StatusPkinitKdcCertificate {
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StatusPkinit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pkinit: Option<bool>,
        #[serde(rename = "anonymousPkinit", default, skip_serializing_if = "Option::is_none")]
        pub anonymous_pkinit: Option<bool>,
        #[serde(rename = "anonymousTickets", default, skip_serializing_if = "Option::is_none")]
        pub anonymous_tickets: Option<String>,
        #[serde(rename = "freshnessRequired", default, skip_serializing_if = "Option::is_none")]
        pub freshness_required: Option<bool>,
        #[serde(rename = "legacyKdf", default, skip_serializing_if = "Option::is_none")]
        pub legacy_kdf: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kdfs: Option<Vec<String>>,
        #[serde(rename = "keyAgreement", default, skip_serializing_if = "Option::is_none")]
        pub key_agreement: Option<Vec<String>>,
        #[serde(rename = "rsaKeyTransport", default, skip_serializing_if = "Option::is_none")]
        pub rsa_key_transport: Option<String>,
        #[serde(rename = "cmsDigests", default, skip_serializing_if = "Option::is_none")]
        pub cms_digests: Option<Vec<String>>,
        #[serde(rename = "clientCertificates", default, skip_serializing_if = "Option::is_none")]
        pub client_certificates: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub indicators: Option<Vec<String>>,
        #[serde(rename = "kdcKeyAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub kdc_key_algorithm: Option<String>,
        #[serde(rename = "kdcCertificate", default, skip_serializing_if = "Option::is_none")]
        pub kdc_certificate: Option<Answer200StatusPkinitKdcCertificate>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Status {
        #[serde(rename = "passwordAloneRefused", default, skip_serializing_if = "Option::is_none")]
        pub password_alone_refused: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fast: Option<bool>,
        #[serde(rename = "armorTypes", default, skip_serializing_if = "Option::is_none")]
        pub armor_types: Option<Vec<String>>,
        #[serde(rename = "fastFactors", default, skip_serializing_if = "Option::is_none")]
        pub fast_factors: Option<Vec<String>>,
        #[serde(rename = "passwordAloneForSecondFactorAccounts", default, skip_serializing_if = "Option::is_none")]
        pub password_alone_for_second_factor_accounts: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub refusal: Option<Option<String>>,
        #[serde(rename = "otpIndicator", default, skip_serializing_if = "Option::is_none")]
        pub otp_indicator: Option<String>,
        #[serde(rename = "notImplemented", default, skip_serializing_if = "Option::is_none")]
        pub not_implemented: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub krbtgt: Option<sts_model_management_components_2::KrbtgtValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pkinit: Option<Answer200StatusPkinit>,
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
        pub status: Option<Answer200Status>,
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
        pub settings: Option<sts_model_management_components_4::WithPageGroupsSettingCount2>,
        #[serde(rename = "leadHtml", default, skip_serializing_if = "Option::is_none")]
        pub lead_html: Option<String>,
        #[serde(rename = "alsoHtml", default, skip_serializing_if = "Option::is_none")]
        pub also_html: Option<Vec<String>>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// The claims a Kerberos ticket's PAC carries
pub mod get_kerberos_pac_claims {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/kerberos/claims";
    pub const OPERATION_ID: &str = "getKerberosPacClaims";

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
    pub struct Answer200SetsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<sts_model_management_components_4::WithOkMessageErrors73>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
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
    pub struct Answer200PreviewClaimsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<sts_model_management_components_4::WithLdapClaimValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dropped: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Preview {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
        pub entry_found: Option<bool>,
        #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
        pub by_ldap: Option<sts_model_management_components_2::DirectoryAttribute>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Vec<Answer200PreviewClaimsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
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
        pub sets: Option<Vec<Answer200SetsItem>>,
        #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
        pub attribute_catalogue: Option<sts_model_management_components_4::WithDescriptionLdapClaim>,
        #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
        pub attribute_choices: Option<Vec<Answer200AttributeChoicesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preview: Option<Answer200Preview>,
    }
}

/// Add one claim to one set
pub mod add_kerberos_pac_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/add";
    pub const OPERATION_ID: &str = "addKerberosPacClaim";

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
pub mod add_kerberos_pac_attribute_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/add-attribute-claim";
    pub const OPERATION_ID: &str = "addKerberosPacAttributeClaim";

    /// The PAC claim type each value becomes; a value that is not one leaves the
    /// claim out of the ticket.
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
        /// The directory attribute.
        pub attribute: String,
        /// Every value rather than the first.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        /// The PAC claim type each value becomes; a value that is not one leaves
        /// the claim out of the ticket.
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
pub mod set_kerberos_pac_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/attributes";
    pub const OPERATION_ID: &str = "setKerberosPacClaimAttributes";

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
pub mod select_all_kerberos_pac_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/attributes-all";
    pub const OPERATION_ID: &str = "selectAllKerberosPacClaimAttributes";

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
pub mod clear_kerberos_pac_claim_attributes {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/attributes-clear";
    pub const OPERATION_ID: &str = "clearKerberosPacClaimAttributes";

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
pub mod clear_kerberos_pac_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/clear";
    pub const OPERATION_ID: &str = "clearKerberosPacClaims";

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
pub mod remove_kerberos_pac_claim {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/remove";
    pub const OPERATION_ID: &str = "removeKerberosPacClaim";

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
pub mod replace_kerberos_pac_claims {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/claims/replace";
    pub const OPERATION_ID: &str = "replaceKerberosPacClaims";

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

/// Who the KDC holds a stored long-term key for
pub mod get_kerberos_principals {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/kerberos/principals";
    pub const OPERATION_ID: &str = "getKerberosPrincipals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "peoplePage", default, skip_serializing_if = "Option::is_none")]
        pub people_page: Option<i64>,
        #[serde(rename = "servicesPage", default, skip_serializing_if = "Option::is_none")]
        pub services_page: Option<i64>,
        #[serde(rename = "databasePage", default, skip_serializing_if = "Option::is_none")]
        pub database_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Retention {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub versions: Option<f64>,
        #[serde(rename = "ttlSeconds", default, skip_serializing_if = "Option::is_none")]
        pub ttl_seconds: Option<f64>,
        #[serde(rename = "ttlSetting", default, skip_serializing_if = "Option::is_none")]
        pub ttl_setting: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Acceptor {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub spn: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(rename = "storedKey", default, skip_serializing_if = "Option::is_none")]
        pub stored_key: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AccountPolicy {
        #[serde(rename = "anyUsernameAuthenticates", default, skip_serializing_if = "Option::is_none")]
        pub any_username_authenticates: Option<bool>,
        #[serde(rename = "neverCreated", default, skip_serializing_if = "Option::is_none")]
        pub never_created: Option<Vec<String>>,
        #[serde(rename = "serviceHosts", default, skip_serializing_if = "Option::is_none")]
        pub service_hosts: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PeopleItemEtypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etype: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PeopleItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retained: Option<sts_model_management_components_2::WithAdditionalPropertiesPropertiesPrincipal>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kvno: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<Answer200PeopleItemEtypesItem>>,
        #[serde(rename = "derivedAt", default, skip_serializing_if = "Option::is_none")]
        pub derived_at: Option<String>,
        #[serde(rename = "derivedOn", default, skip_serializing_if = "Option::is_none")]
        pub derived_on: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sealed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ServicesItemEtypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etype: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ServicesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retained: Option<sts_model_management_components_2::WithAdditionalPropertiesPropertiesPrincipal>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kvno: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<Answer200ServicesItemEtypesItem>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
        pub created_at: Option<String>,
        #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none")]
        pub rotated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sealed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DatabaseItemEtypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etype: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DatabaseItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
        #[serde(rename = "nameType", default, skip_serializing_if = "Option::is_none")]
        pub name_type: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub salt: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub etypes: Option<Vec<Answer200DatabaseItemEtypesItem>>,
        #[serde(rename = "requiresPreAuth", default, skip_serializing_if = "Option::is_none")]
        pub requires_pre_auth: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<bool>,
        #[serde(rename = "passwordExpired", default, skip_serializing_if = "Option::is_none")]
        pub password_expired: Option<bool>,
        #[serde(rename = "okAsDelegate", default, skip_serializing_if = "Option::is_none")]
        pub ok_as_delegate: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kvno: Option<f64>,
        #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
        pub auto_created: Option<bool>,
        #[serde(rename = "directoryKeys", default, skip_serializing_if = "Option::is_none")]
        pub directory_keys: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Notes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub installed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub trust_realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos: Option<sts_model_management_components_4::WithTrustRealmKerberosRealmEnabled>,
        #[serde(rename = "productKdc", default, skip_serializing_if = "Option::is_none")]
        pub product_kdc: Option<bool>,
        #[serde(rename = "personKeys", default, skip_serializing_if = "Option::is_none")]
        pub person_keys: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enctypes: Option<Vec<i64>>,
        #[serde(rename = "startingKvno", default, skip_serializing_if = "Option::is_none")]
        pub starting_kvno: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retention: Option<Answer200Retention>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub acceptor: Option<Answer200Acceptor>,
        #[serde(rename = "accountPolicy", default, skip_serializing_if = "Option::is_none")]
        pub account_policy: Option<Answer200AccountPolicy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub krbtgt: Option<sts_model_management_components_2::KrbtgtValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<Vec<Answer200PeopleItem>>,
        #[serde(rename = "peopleTotal", default, skip_serializing_if = "Option::is_none")]
        pub people_total: Option<i64>,
        #[serde(rename = "peoplePaging", default, skip_serializing_if = "Option::is_none")]
        pub people_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub services: Option<Vec<Answer200ServicesItem>>,
        #[serde(rename = "servicesTotal", default, skip_serializing_if = "Option::is_none")]
        pub services_total: Option<i64>,
        #[serde(rename = "servicesPaging", default, skip_serializing_if = "Option::is_none")]
        pub services_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(rename = "fixtureAccounts", default, skip_serializing_if = "Option::is_none")]
        pub fixture_accounts: Option<bool>,
        #[serde(rename = "realmsServed", default, skip_serializing_if = "Option::is_none")]
        pub realms_served: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub database: Option<Vec<Answer200DatabaseItem>>,
        #[serde(rename = "databaseTotal", default, skip_serializing_if = "Option::is_none")]
        pub database_total: Option<i64>,
        #[serde(rename = "databasePaging", default, skip_serializing_if = "Option::is_none")]
        pub database_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<Answer200Notes>,
    }
}

/// Clear a directory person's Kerberos keys
pub mod clear_kerberos_person_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/clear-person-keys";
    pub const OPERATION_ID: &str = "clearKerberosPersonKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as they sign in — in the default trust realm's directory.
        pub username: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors131;
}

/// Create a service principal with a random key, and get its keytab once
pub mod create_kerberos_service_principal {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/create-service";
    pub const OPERATION_ID: &str = "createKerberosServicePrincipal";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service principal name, e.g. `HTTP/web.example.com`, with or without
        /// `@<realm>`.
        pub spn: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors129;
}

/// Delete a service principal's stored key
pub mod delete_kerberos_service_principal {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/delete-service";
    pub const OPERATION_ID: &str = "deleteKerberosServicePrincipal";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service principal name.
        pub spn: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors130;
}

/// Stop accepting tickets under a person's previous key versions, now
pub mod drop_kerberos_person_previous_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/drop-previous-person-keys";
    pub const OPERATION_ID: &str = "dropKerberosPersonPreviousKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as they sign in — in the default trust realm's directory.
        pub username: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors132;
}

/// Stop accepting tickets under a service principal's previous key versions,
/// now
pub mod drop_kerberos_service_previous_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/drop-previous-service-keys";
    pub const OPERATION_ID: &str = "dropKerberosServicePreviousKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service principal name.
        pub spn: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors132;
}

/// Reset a person's password, and get the keytab derived from it once
pub mod reset_kerberos_person_keytab {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/reset-person-keytab";
    pub const OPERATION_ID: &str = "resetKerberosPersonKeytab";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, as they sign in, in the trust realm of the call.
        pub username: String,
        /// The new password. Leave out with `random`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// A generated password under the password policy, never returned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub random: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors133;
}

/// Rotate the realm's krbtgt key, keeping the one it replaces for the TGTs
/// already sealed under it
pub mod rotate_kerberos_krbtgt {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/rotate-krbtgt";
    pub const OPERATION_ID: &str = "rotateKerberosKrbtgt";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors134;
}

/// Rotate the realm's krbtgt key and keep NOTHING, so every TGT in the realm is
/// refused
pub mod rotate_kerberos_krbtgt_invalidate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/rotate-krbtgt-invalidate";
    pub const OPERATION_ID: &str = "rotateKerberosKrbtgtInvalidate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The word `invalidate`, because this cannot be undone.
        pub confirm: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors134;
}

/// Replace a service principal's key, and get the new keytab once
pub mod rotate_kerberos_service_principal {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/principals/rotate-service";
    pub const OPERATION_ID: &str = "rotateKerberosServicePrincipal";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The service principal name.
        pub spn: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors129;
}

/// The realm's Kerberos trusts, with their keys described and never carried
pub mod get_kerberos_trusts {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/kerberos/trusts";
    pub const OPERATION_ID: &str = "getKerberosTrusts";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "trustsPage", default, skip_serializing_if = "Option::is_none")]
        pub trusts_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trust: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TrustsItemOutgoing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kvno: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "setAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub set_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principal: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TrustsItemEnctypeNamesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TrustsItem {
        #[serde(rename = "partnerRealm", default, skip_serializing_if = "Option::is_none")]
        pub partner_realm: Option<String>,
        #[serde(rename = "netbiosName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub netbios_name: Option<Option<String>>,
        #[serde(rename = "partnerSid", default, skip_serializing_if = "Option::is_none")]
        pub partner_sid: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(rename = "partnerTrustRealm", default, skip_serializing_if = "Option::is_none")]
        pub partner_trust_realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub direction: Option<String>,
        #[serde(rename = "trustDirection", default, skip_serializing_if = "Option::is_none")]
        pub trust_direction: Option<i64>,
        #[serde(rename = "trustAttributes", default, skip_serializing_if = "Option::is_none")]
        pub trust_attributes: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suffixes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enctypes: Option<Vec<i64>>,
        #[serde(rename = "forestTrustInfo", default, skip_serializing_if = "Option::is_none")]
        pub forest_trust_info: Option<sts_model_management_components_2::ForestTrustInfoValue>,
        #[serde(rename = "claimsTransformation", default, skip_serializing_if = "Option::is_none")]
        pub claims_transformation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub boundary: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub incoming: Option<sts_model_management_components_3::WithPreviousHeldKvno>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outgoing: Option<Answer200TrustsItemOutgoing>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<String>>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub updated_at: Option<Option<String>>,
        #[serde(rename = "enctypeNames", default, skip_serializing_if = "Option::is_none")]
        pub enctype_names: Option<Vec<Answer200TrustsItemEnctypeNamesItem>>,
        #[serde(rename = "lastKeyChangeAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_key_change_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub health: Option<sts_model_management_components_3::WithAdditionalPropertiesPropertiesPartnerRealm>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormContradictionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub a: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub b: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormRequiresItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub needs: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormEnctypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormTrustRealmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "kerberosRealm", default, skip_serializing_if = "Option::is_none")]
        pub kerberos_realm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Form {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        #[serde(rename = "defaultAttributes", default, skip_serializing_if = "Option::is_none")]
        pub default_attributes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub contradictions: Option<Vec<Answer200FormContradictionsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requires: Option<Vec<Answer200FormRequiresItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directions: Option<Vec<String>>,
        #[serde(rename = "keySources", default, skip_serializing_if = "Option::is_none")]
        pub key_sources: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enctypes: Option<Vec<Answer200FormEnctypesItem>>,
        #[serde(rename = "defaultEnctypes", default, skip_serializing_if = "Option::is_none")]
        pub default_enctypes: Option<Vec<i64>>,
        #[serde(rename = "claimsTransformations", default, skip_serializing_if = "Option::is_none")]
        pub claims_transformations: Option<Vec<String>>,
        #[serde(rename = "minPasswordLength", default, skip_serializing_if = "Option::is_none")]
        pub min_password_length: Option<i64>,
        #[serde(rename = "trustRealms", default, skip_serializing_if = "Option::is_none")]
        pub trust_realms: Option<Vec<Answer200FormTrustRealmsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Settings {
        #[serde(rename = "crossRealmClassicDelegation", default, skip_serializing_if = "Option::is_none")]
        pub cross_realm_classic_delegation: Option<bool>,
        #[serde(rename = "requireSidFilteringInProduct", default, skip_serializing_if = "Option::is_none")]
        pub require_sid_filtering_in_product: Option<bool>,
        #[serde(rename = "maxReferralHops", default, skip_serializing_if = "Option::is_none")]
        pub max_referral_hops: Option<f64>,
        #[serde(rename = "trustKeyGraceSeconds", default, skip_serializing_if = "Option::is_none")]
        pub trust_key_grace_seconds: Option<f64>,
        #[serde(rename = "graceSeconds", default, skip_serializing_if = "Option::is_none")]
        pub grace_seconds: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub trust_realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kerberos: Option<sts_model_management_components_4::WithTrustRealmKerberosRealmEnabled>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trusts: Option<Vec<Answer200TrustsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(rename = "trustsPaging", default, skip_serializing_if = "Option::is_none")]
        pub trusts_paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trust: Option<sts_model_management_components_3::TrustValue>,
        #[serde(rename = "unknownTrust", default, skip_serializing_if = "Option::is_none")]
        pub unknown_trust: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub product: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub form: Option<Answer200Form>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Answer200Settings>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
    }
}

/// Add a trust with another Kerberos realm
pub mod add_kerberos_trust {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/add";
    pub const OPERATION_ID: &str = "addKerberosTrust";

    /// `external` — a KDC elsewhere — or `trust-realm`, another trust realm of this
    /// service.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "external")]
        External,
        #[serde(rename = "trust-realm")]
        TrustRealm,
    }

    /// Which keys the record holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDirection {
        #[serde(rename = "bidirectional")]
        Bidirectional,
        #[serde(rename = "inbound")]
        Inbound,
        #[serde(rename = "outbound")]
        Outbound,
    }

    /// Where a key it does not hold yet comes from.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeySource {
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "generate")]
        Generate,
    }

    /// What becomes of a claims set arriving across it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyClaimsTransformation {
        #[serde(rename = "drop-all")]
        DropAll,
        #[serde(rename = "allow-all")]
        AllowAll,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The partner Kerberos realm, PARTNER.EXAMPLE.
        #[serde(rename = "partnerRealm")]
        pub partner_realm: String,
        /// Its NetBIOS (flat) name; the realm's first label by default.
        #[serde(rename = "netbiosName", default, skip_serializing_if = "Option::is_none")]
        pub netbios_name: Option<String>,
        /// Its domain SID, S-1-5-21-a-b-c; a trust realm's own by default.
        #[serde(rename = "partnerSid", default, skip_serializing_if = "Option::is_none")]
        pub partner_sid: Option<String>,
        /// `external` — a KDC elsewhere — or `trust-realm`, another trust realm of
        /// this service.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// For `trust-realm`: that trust realm's id.
        #[serde(rename = "partnerTrustRealm", default, skip_serializing_if = "Option::is_none")]
        pub partner_trust_realm: Option<String>,
        /// Which keys the record holds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub direction: Option<BodyDirection>,
        /// Where a key it does not hold yet comes from.
        #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
        pub key_source: Option<BodyKeySource>,
        /// The shared trust password, for `keySource: "password"`. Never shown
        /// back.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// [MS-ADTS] 6.1.6.7.9's bits by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        /// Set by the console's form: the attribute boxes were drawn.
        #[serde(rename = "attributesShown", default, skip_serializing_if = "Option::is_none")]
        pub attributes_shown: Option<String>,
        /// The DNS suffixes routed to the partner.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suffixes: Option<sts_model_base::unions::StringOrList>,
        /// The enctypes its keys are made for, by number; AES by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enctypes: Option<sts_model_base::unions::StringOrList>,
        /// What becomes of a claims set arriving across it.
        #[serde(rename = "claimsTransformation", default, skip_serializing_if = "Option::is_none")]
        pub claims_transformation: Option<BodyClaimsTransformation>,
        /// A cross-forest trust's { domains: [{ sid, dnsName, netbiosName,
        /// sidEnabled }], topLevelNames: [{ name, enabled }] }.
        #[serde(rename = "forestTrustInfo", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub forest_trust_info: Option<Option<sts_model_base::unions::StringOrObject>>,
        /// The form's text: a domain per line, `<sid> <dns name> <netbios name>
        /// [disabled]`.
        #[serde(rename = "forestDomains", default, skip_serializing_if = "Option::is_none")]
        pub forest_domains: Option<String>,
        /// The form's text: a top-level name per line, `<name> [disabled]`.
        #[serde(rename = "forestNames", default, skip_serializing_if = "Option::is_none")]
        pub forest_names: Option<String>,
        /// Whether it is used; true by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// Turn a trust off, keeping its keys
pub mod disable_kerberos_trust {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/disable";
    pub const OPERATION_ID: &str = "disableKerberosTrust";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The partner Kerberos realm.
        #[serde(rename = "partnerRealm")]
        pub partner_realm: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// Turn a trust on
pub mod enable_kerberos_trust {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/enable";
    pub const OPERATION_ID: &str = "enableKerberosTrust";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The partner Kerberos realm.
        #[serde(rename = "partnerRealm")]
        pub partner_realm: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// Write the matching record on the partner trust realm
pub mod pair_kerberos_trust {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/pair";
    pub const OPERATION_ID: &str = "pairKerberosTrust";

    /// With `otherRealm`: the keys, from this realm's side.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDirection {
        #[serde(rename = "bidirectional")]
        Bidirectional,
        #[serde(rename = "inbound")]
        Inbound,
        #[serde(rename = "outbound")]
        Outbound,
    }

    /// With `otherRealm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeySource {
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "generate")]
        Generate,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A record held here, to mirror.
        #[serde(rename = "partnerRealm", default, skip_serializing_if = "Option::is_none")]
        pub partner_realm: Option<String>,
        /// A trust realm's id, to pair from nothing.
        #[serde(rename = "otherRealm", default, skip_serializing_if = "Option::is_none")]
        pub other_realm: Option<String>,
        /// With `otherRealm`: the keys, from this realm's side.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub direction: Option<BodyDirection>,
        /// With `otherRealm`.
        #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
        pub key_source: Option<BodyKeySource>,
        /// With `keySource: "password"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// With `otherRealm`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        /// With `otherRealm`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enctypes: Option<sts_model_base::unions::StringOrList>,
        /// With `otherRealm`: what this realm routes to the other.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suffixes: Option<sts_model_base::unions::StringOrList>,
        /// With `otherRealm`: what the other routes here.
        #[serde(rename = "partnerSuffixes", default, skip_serializing_if = "Option::is_none")]
        pub partner_suffixes: Option<sts_model_base::unions::StringOrList>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// Remove a trust and its keys
pub mod remove_kerberos_trust {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/remove";
    pub const OPERATION_ID: &str = "removeKerberosTrust";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The partner Kerberos realm.
        #[serde(rename = "partnerRealm")]
        pub partner_realm: String,
        /// The partner realm again.
        pub confirm: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// Replace a trust's keys at the next kvno, keeping the incoming one for a
/// grace
pub mod rotate_kerberos_trust_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/rotate-key";
    pub const OPERATION_ID: &str = "rotateKerberosTrustKey";

    /// Which keys.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySide {
        #[serde(rename = "both")]
        Both,
        #[serde(rename = "incoming")]
        Incoming,
        #[serde(rename = "outgoing")]
        Outgoing,
    }

    /// Where the new key comes from.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeySource {
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "generate")]
        Generate,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The partner Kerberos realm.
        #[serde(rename = "partnerRealm")]
        pub partner_realm: String,
        /// Which keys.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub side: Option<BodySide>,
        /// Where the new key comes from.
        #[serde(rename = "keySource")]
        pub key_source: BodyKeySource,
        /// The new trust password, for `keySource: "password"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// Rotate the partner trust realm's record too.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mirror: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// Change a trust's fields
pub mod update_kerberos_trust {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/kerberos/trusts/update";
    pub const OPERATION_ID: &str = "updateKerberosTrust";

    /// `external` — a KDC elsewhere — or `trust-realm`, another trust realm of this
    /// service.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyType {
        #[serde(rename = "external")]
        External,
        #[serde(rename = "trust-realm")]
        TrustRealm,
    }

    /// Which keys the record holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDirection {
        #[serde(rename = "bidirectional")]
        Bidirectional,
        #[serde(rename = "inbound")]
        Inbound,
        #[serde(rename = "outbound")]
        Outbound,
    }

    /// Where a key it does not hold yet comes from.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeySource {
        #[serde(rename = "password")]
        Password,
        #[serde(rename = "generate")]
        Generate,
    }

    /// What becomes of a claims set arriving across it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyClaimsTransformation {
        #[serde(rename = "drop-all")]
        DropAll,
        #[serde(rename = "allow-all")]
        AllowAll,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The partner Kerberos realm, PARTNER.EXAMPLE.
        #[serde(rename = "partnerRealm")]
        pub partner_realm: String,
        /// Its NetBIOS (flat) name; the realm's first label by default.
        #[serde(rename = "netbiosName", default, skip_serializing_if = "Option::is_none")]
        pub netbios_name: Option<String>,
        /// Its domain SID, S-1-5-21-a-b-c; a trust realm's own by default.
        #[serde(rename = "partnerSid", default, skip_serializing_if = "Option::is_none")]
        pub partner_sid: Option<String>,
        /// `external` — a KDC elsewhere — or `trust-realm`, another trust realm of
        /// this service.
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<BodyType>,
        /// For `trust-realm`: that trust realm's id.
        #[serde(rename = "partnerTrustRealm", default, skip_serializing_if = "Option::is_none")]
        pub partner_trust_realm: Option<String>,
        /// Which keys the record holds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub direction: Option<BodyDirection>,
        /// Where a key it does not hold yet comes from.
        #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
        pub key_source: Option<BodyKeySource>,
        /// The shared trust password, for `keySource: "password"`. Never shown
        /// back.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// [MS-ADTS] 6.1.6.7.9's bits by name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        /// Set by the console's form: the attribute boxes were drawn.
        #[serde(rename = "attributesShown", default, skip_serializing_if = "Option::is_none")]
        pub attributes_shown: Option<String>,
        /// The DNS suffixes routed to the partner.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suffixes: Option<sts_model_base::unions::StringOrList>,
        /// The enctypes its keys are made for, by number; AES by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enctypes: Option<sts_model_base::unions::StringOrList>,
        /// What becomes of a claims set arriving across it.
        #[serde(rename = "claimsTransformation", default, skip_serializing_if = "Option::is_none")]
        pub claims_transformation: Option<BodyClaimsTransformation>,
        /// A cross-forest trust's { domains: [{ sid, dnsName, netbiosName,
        /// sidEnabled }], topLevelNames: [{ name, enabled }] }.
        #[serde(rename = "forestTrustInfo", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub forest_trust_info: Option<Option<sts_model_base::unions::StringOrObject>>,
        /// The form's text: a domain per line, `<sid> <dns name> <netbios name>
        /// [disabled]`.
        #[serde(rename = "forestDomains", default, skip_serializing_if = "Option::is_none")]
        pub forest_domains: Option<String>,
        /// The form's text: a top-level name per line, `<name> [disabled]`.
        #[serde(rename = "forestNames", default, skip_serializing_if = "Option::is_none")]
        pub forest_names: Option<String>,
        /// Whether it is used; true by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors135;
}

/// The embedded directory's own settings
pub mod get_ldap_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap";
    pub const OPERATION_ID: &str = "getLdapSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat2;
}

/// The application registry as the directory holds it, and its schema
pub mod get_directory_applications {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/applications";
    pub const OPERATION_ID: &str = "getDirectoryApplications";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryApplicationList;
}

/// The device register as the directory holds it, and its schema
pub mod get_directory_devices {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/devices";
    pub const OPERATION_ID: &str = "getDirectoryDevices";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
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
        pub q: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SchemaObjectClassesItem {
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
    pub struct Answer200SchemaAttributesItem {
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
    pub struct Answer200Schema {
        #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
        pub object_classes: Option<Vec<Answer200SchemaObjectClassesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<Answer200SchemaAttributesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EntriesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        /// Attribute names, which are data in a schemaless directory, and values.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Search {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub complete: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scanned: Option<i64>,
        #[serde(rename = "scanLimit", default, skip_serializing_if = "Option::is_none")]
        pub scan_limit: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
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
        pub filter: Option<Answer200Filter>,
        #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
        pub source_of_truth: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schema: Option<Answer200Schema>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<Vec<Answer200EntriesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub search: Option<Answer200Search>,
        #[serde(rename = "pageCap", default, skip_serializing_if = "Option::is_none")]
        pub page_cap: Option<i64>,
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
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub directory: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }
}

/// Every entry in this realm's directory, paged
pub mod get_directory_entries {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/directory";
    pub const OPERATION_ID: &str = "getDirectoryEntries";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryEntryList;
}

/// The federation register as the directory holds it, and its schema
pub mod get_directory_federations {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/federations";
    pub const OPERATION_ID: &str = "getDirectoryFederations";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryFederationList;
}

/// The registered remote PEPs as the directory holds them, and their schema
pub mod get_directory_peps {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/peps";
    pub const OPERATION_ID: &str = "getDirectoryPeps";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryPepList;
}

/// The policy repository as the directory holds it, and its schema
pub mod get_directory_policies {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/policies";
    pub const OPERATION_ID: &str = "getDirectoryPolicies";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryPolicyList;
}

/// The role entries as the directory holds them, and their schema
pub mod get_directory_roles {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/roles";
    pub const OPERATION_ID: &str = "getDirectoryRoles";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryRoleList;
}

/// What the embedded directory IS, right now
pub mod get_directory_service {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/service";
    pub const OPERATION_ID: &str = "getDirectoryService";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectoryService;
}

/// The two SPIFFE containers as the directory holds them, and their schema
pub mod get_directory_spiffe {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ldap/spiffe";
    pub const OPERATION_ID: &str = "getDirectorySpiffe";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entryq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agentq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "entriesPage", default, skip_serializing_if = "Option::is_none")]
        pub entries_page: Option<i64>,
        #[serde(rename = "agentsPage", default, skip_serializing_if = "Option::is_none")]
        pub agents_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::DirectorySpiffe;
}

/// Every call, every artifact, and both kinds of session
pub mod get_metrics {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/metrics";
    pub const OPERATION_ID: &str = "getMetrics";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::Metrics;
}

/// Who holds a second factor, and how RFC 6238 is configured here
pub mod get_multi_factor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/mfa";
    pub const OPERATION_ID: &str = "getMultiFactor";

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

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub factor: Option<QueryFactor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
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
        #[serde(rename = "passwordOnly", default, skip_serializing_if = "Option::is_none")]
        pub password_only: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unreadable: Option<f64>,
        #[serde(rename = "noCredential", default, skip_serializing_if = "Option::is_none")]
        pub no_credential: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DirectoryCounts {
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
    pub struct Answer200Filter {
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
    pub struct Answer200PeopleItemTotpDetail {
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
    pub struct Answer200PeopleItemBackupCodes {
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
    pub struct Answer200PeopleItem {
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
        pub totp_detail: Option<Answer200PeopleItemTotpDetail>,
        #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
        pub backup_codes: Option<Answer200PeopleItemBackupCodes>,
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
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totp: Option<sts_model_management_components_4::WithOfferedDigitsSecretBits>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub webauthn: Option<sts_model_management_components_4::WithOfferedRpNameRpId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
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
        pub directory_counts: Option<Answer200DirectoryCounts>,
        #[serde(rename = "directoryCountedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub directory_counted_at: Option<Option<String>>,
        #[serde(rename = "directoryCountsKeptFor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub directory_counts_kept_for: Option<Option<f64>>,
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
        pub matched: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shown: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<Vec<Answer200PeopleItem>>,
    }
}

/// Turn off somebody's emailed second factor
pub mod clear_email_factor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mfa/clear-email-factor";
    pub const OPERATION_ID: &str = "clearEmailFactor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The name they sign in as.
        pub username: String,
        /// Accepted for `username`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
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
pub mod clear_security_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mfa/clear-key";
    pub const OPERATION_ID: &str = "clearSecurityKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        pub username: String,
        /// Accepted for `username`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
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
pub mod clear_authenticator_app {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mfa/clear-totp";
    pub const OPERATION_ID: &str = "clearAuthenticatorApp";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// How the person's identity was verified, in at least 8 characters.
        /// Product mode requires it, and it is recorded in the audit log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<String>,
        /// The name they sign in as.
        pub username: String,
        /// Accepted for `username`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors20;
}

/// Who holds which passkey algorithm, across the realm (#942)
pub mod get_passkey_report {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/passkey-report";
    pub const OPERATION_ID: &str = "getPasskeyReport";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryList {
        #[serde(rename = "post-quantum-only")]
        PostQuantumOnly,
        #[serde(rename = "classical-only")]
        ClassicalOnly,
        #[serde(rename = "both")]
        Both,
        #[serde(rename = "none")]
        None,
        #[serde(rename = "holding")]
        Holding,
        #[serde(rename = "algorithm")]
        Algorithm,
        #[serde(rename = "model")]
        Model,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryLane {
        #[serde(rename = "classical")]
        Classical,
        #[serde(rename = "pqc")]
        Pqc,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub list: Option<QueryList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<QueryLane>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Limits {
        #[serde(rename = "listScan", default, skip_serializing_if = "Option::is_none")]
        pub list_scan: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub population: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub export: Option<i64>,
        #[serde(rename = "perMax", default, skip_serializing_if = "Option::is_none")]
        pub per_max: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Recount {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub every: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counted {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub started_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "durationMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub duration_ms: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub holders: Option<Option<f64>>,
        #[serde(rename = "changesSince", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub changes_since: Option<Option<f64>>,
        #[serde(rename = "lastChangeAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_change_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PopulationGroupsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub asked: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dn: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Population {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<Answer200PopulationGroupsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub members: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub read: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub complete: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Application {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub named: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub applies: Option<Option<String>>,
        #[serde(rename = "groupPolicies", default, skip_serializing_if = "Option::is_none")]
        pub group_policies: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200People {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub total: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holding: Option<f64>,
        #[serde(rename = "postQuantumOnly", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum_only: Option<f64>,
        #[serde(rename = "classicalOnly", default, skip_serializing_if = "Option::is_none")]
        pub classical_only: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub both: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub none: Option<Option<f64>>,
        #[serde(rename = "withPostQuantum", default, skip_serializing_if = "Option::is_none")]
        pub with_post_quantum: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysByAlgorithmItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cose_alg: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Keys {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classical: Option<f64>,
        #[serde(rename = "byLane", default, skip_serializing_if = "Option::is_none")]
        pub by_lane: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "byAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub by_algorithm: Option<Vec<Answer200KeysByAlgorithmItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ModelsItemAlgorithmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cose_alg: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ModelsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Vec<Answer200ModelsItemAlgorithmsItem>>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AttestationRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cose_alg: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<String>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Attestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recorded: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200AttestationRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub param: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub noun: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub total: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pages: Option<Option<i64>>,
        #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
        pub first_row: Option<i64>,
        #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
        pub last_row: Option<i64>,
        #[serde(rename = "nextFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub next_from: Option<Option<String>>,
        #[serde(rename = "hasNext", default, skip_serializing_if = "Option::is_none")]
        pub has_next: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scanned: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub complete: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub list: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub algorithm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub lane: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<sts_model_management_components_4::WithOkMessageErrors185>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200ListPaging>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<sts_model_management_components_4::WithNamePostQuantumRequiredPrecedence>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lists: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kinds: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<Answer200Limits>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recount: Option<Answer200Recount>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub installed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counted: Option<Answer200Counted>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub population: Option<Answer200Population>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<sts_model_management_components_4::WithNamePostQuantumRequiredPrecedence>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<Answer200Application>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<Answer200People>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Answer200Keys>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub models: Option<Vec<Answer200ModelsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestation: Option<Answer200Attestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub list: Option<Answer200List>,
    }
}

/// Download one passkey RFC 4998 evidence record (#947)
pub mod export_passkey_attestation_evidence {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/passkey-report/evidence";
    pub const OPERATION_ID: &str = "exportPasskeyAttestationEvidence";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub username: String,
        #[serde(rename = "credentialId")]
        pub credential_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
        pub credential_id: Option<String>,
        /// The attestation statement an authenticator sent, archived as it was: its
        /// members are WebAuthn's per attestation format.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evidence: Option<serde_json::Value>,
    }
}

/// Every person behind one passkey count, as CSV or JSON
pub mod export_passkey_report {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/passkey-report/export";
    pub const OPERATION_ID: &str = "exportPasskeyReport";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryList {
        #[serde(rename = "post-quantum-only")]
        PostQuantumOnly,
        #[serde(rename = "classical-only")]
        ClassicalOnly,
        #[serde(rename = "both")]
        Both,
        #[serde(rename = "none")]
        None,
        #[serde(rename = "holding")]
        Holding,
        #[serde(rename = "algorithm")]
        Algorithm,
        #[serde(rename = "model")]
        Model,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryLane {
        #[serde(rename = "classical")]
        Classical,
        #[serde(rename = "pqc")]
        Pqc,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryFormat {
        #[serde(rename = "csv")]
        Csv,
        #[serde(rename = "json")]
        Json,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub list: Option<QueryList>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lane: Option<QueryLane>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aaguid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub list: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub truncated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<sts_model_management_components_4::WithOkMessageErrors185>,
    }
}

/// Count the realm's passkeys again, now
pub mod recount_passkey_report {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/passkey-report/recount";
    pub const OPERATION_ID: &str = "recountPasskeyReport";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors186;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "addAuditExportDestination" => Some(serde_json::from_value::<add_audit_export_destination::Body>(value.clone()).map(|_| ())),
        "disableAuditExportDestination" => Some(serde_json::from_value::<disable_audit_export_destination::Body>(value.clone()).map(|_| ())),
        "enableAuditExportDestination" => Some(serde_json::from_value::<enable_audit_export_destination::Body>(value.clone()).map(|_| ())),
        "removeAuditExportDestination" => Some(serde_json::from_value::<remove_audit_export_destination::Body>(value.clone()).map(|_| ())),
        "testAuditExportDestination" => Some(serde_json::from_value::<test_audit_export_destination::Body>(value.clone()).map(|_| ())),
        "updateAuditExportDestination" => Some(serde_json::from_value::<update_audit_export_destination::Body>(value.clone()).map(|_| ())),
        "retryOutboundDelivery" => Some(serde_json::from_value::<retry_outbound_delivery::Body>(value.clone()).map(|_| ())),
        "addFederationValue" => Some(serde_json::from_value::<add_federation_value::Body>(value.clone()).map(|_| ())),
        "checkFederationPartner" => Some(serde_json::from_value::<check_federation_partner::Body>(value.clone()).map(|_| ())),
        "createFederationRelationship" => Some(serde_json::from_value::<create_federation_relationship::Body>(value.clone()).map(|_| ())),
        "deleteFederationRelationship" => Some(serde_json::from_value::<delete_federation_relationship::Body>(value.clone()).map(|_| ())),
        "disableFederationRelationship" => Some(serde_json::from_value::<disable_federation_relationship::Body>(value.clone()).map(|_| ())),
        "enableFederationRelationship" => Some(serde_json::from_value::<enable_federation_relationship::Body>(value.clone()).map(|_| ())),
        "registerAtFederationPartner" => Some(serde_json::from_value::<register_at_federation_partner::Body>(value.clone()).map(|_| ())),
        "removeFederationValue" => Some(serde_json::from_value::<remove_federation_value::Body>(value.clone()).map(|_| ())),
        "rotateFederationKey" => Some(serde_json::from_value::<rotate_federation_key::Body>(value.clone()).map(|_| ())),
        "setFederationField" => Some(serde_json::from_value::<set_federation_field::Body>(value.clone()).map(|_| ())),
        "addFederationSignalsSubject" => Some(serde_json::from_value::<add_federation_signals_subject::Body>(value.clone()).map(|_| ())),
        "createFederationSignalsStream" => Some(serde_json::from_value::<create_federation_signals_stream::Body>(value.clone()).map(|_| ())),
        "deleteFederationSignalsStream" => Some(serde_json::from_value::<delete_federation_signals_stream::Body>(value.clone()).map(|_| ())),
        "discoverFederationSignals" => Some(serde_json::from_value::<discover_federation_signals::Body>(value.clone()).map(|_| ())),
        "pollFederationSignals" => Some(serde_json::from_value::<poll_federation_signals::Body>(value.clone()).map(|_| ())),
        "readFederationSignalsStatus" => Some(serde_json::from_value::<read_federation_signals_status::Body>(value.clone()).map(|_| ())),
        "readFederationSignalsStream" => Some(serde_json::from_value::<read_federation_signals_stream::Body>(value.clone()).map(|_| ())),
        "removeFederationSignalsSubject" => Some(serde_json::from_value::<remove_federation_signals_subject::Body>(value.clone()).map(|_| ())),
        "replaceFederationSignalsStream" => Some(serde_json::from_value::<replace_federation_signals_stream::Body>(value.clone()).map(|_| ())),
        "setFederationSignalsStatus" => Some(serde_json::from_value::<set_federation_signals_status::Body>(value.clone()).map(|_| ())),
        "unblockFederationSignals" => Some(serde_json::from_value::<unblock_federation_signals::Body>(value.clone()).map(|_| ())),
        "updateFederationSignalsStream" => Some(serde_json::from_value::<update_federation_signals_stream::Body>(value.clone()).map(|_| ())),
        "verifyFederationSignalsStream" => Some(serde_json::from_value::<verify_federation_signals_stream::Body>(value.clone()).map(|_| ())),
        "deleteGnapResourceSet" => Some(serde_json::from_value::<delete_gnap_resource_set::Body>(value.clone()).map(|_| ())),
        "revokeGnapGrant" => Some(serde_json::from_value::<revoke_gnap_grant::Body>(value.clone()).map(|_| ())),
        "addGroupMember" => Some(serde_json::from_value::<add_group_member::Body>(value.clone()).map(|_| ())),
        "addGroupOwner" => Some(serde_json::from_value::<add_group_owner::Body>(value.clone()).map(|_| ())),
        "createGroup" => Some(serde_json::from_value::<create_group::Body>(value.clone()).map(|_| ())),
        "removeGroupOwner" => Some(serde_json::from_value::<remove_group_owner::Body>(value.clone()).map(|_| ())),
        "setGroupMail" => Some(serde_json::from_value::<set_group_mail::Body>(value.clone()).map(|_| ())),
        "setGroupPolicy" => Some(serde_json::from_value::<set_group_policy::Body>(value.clone()).map(|_| ())),
        "addKerberosPacClaim" => Some(serde_json::from_value::<add_kerberos_pac_claim::Body>(value.clone()).map(|_| ())),
        "addKerberosPacAttributeClaim" => Some(serde_json::from_value::<add_kerberos_pac_attribute_claim::Body>(value.clone()).map(|_| ())),
        "setKerberosPacClaimAttributes" => Some(serde_json::from_value::<set_kerberos_pac_claim_attributes::Body>(value.clone()).map(|_| ())),
        "selectAllKerberosPacClaimAttributes" => Some(serde_json::from_value::<select_all_kerberos_pac_claim_attributes::Body>(value.clone()).map(|_| ())),
        "clearKerberosPacClaimAttributes" => Some(serde_json::from_value::<clear_kerberos_pac_claim_attributes::Body>(value.clone()).map(|_| ())),
        "clearKerberosPacClaims" => Some(serde_json::from_value::<clear_kerberos_pac_claims::Body>(value.clone()).map(|_| ())),
        "removeKerberosPacClaim" => Some(serde_json::from_value::<remove_kerberos_pac_claim::Body>(value.clone()).map(|_| ())),
        "replaceKerberosPacClaims" => Some(serde_json::from_value::<replace_kerberos_pac_claims::Body>(value.clone()).map(|_| ())),
        "clearKerberosPersonKeys" => Some(serde_json::from_value::<clear_kerberos_person_keys::Body>(value.clone()).map(|_| ())),
        "createKerberosServicePrincipal" => Some(serde_json::from_value::<create_kerberos_service_principal::Body>(value.clone()).map(|_| ())),
        "deleteKerberosServicePrincipal" => Some(serde_json::from_value::<delete_kerberos_service_principal::Body>(value.clone()).map(|_| ())),
        "dropKerberosPersonPreviousKeys" => Some(serde_json::from_value::<drop_kerberos_person_previous_keys::Body>(value.clone()).map(|_| ())),
        "dropKerberosServicePreviousKeys" => Some(serde_json::from_value::<drop_kerberos_service_previous_keys::Body>(value.clone()).map(|_| ())),
        "resetKerberosPersonKeytab" => Some(serde_json::from_value::<reset_kerberos_person_keytab::Body>(value.clone()).map(|_| ())),
        "rotateKerberosKrbtgt" => Some(serde_json::from_value::<rotate_kerberos_krbtgt::Body>(value.clone()).map(|_| ())),
        "rotateKerberosKrbtgtInvalidate" => Some(serde_json::from_value::<rotate_kerberos_krbtgt_invalidate::Body>(value.clone()).map(|_| ())),
        "rotateKerberosServicePrincipal" => Some(serde_json::from_value::<rotate_kerberos_service_principal::Body>(value.clone()).map(|_| ())),
        "addKerberosTrust" => Some(serde_json::from_value::<add_kerberos_trust::Body>(value.clone()).map(|_| ())),
        "disableKerberosTrust" => Some(serde_json::from_value::<disable_kerberos_trust::Body>(value.clone()).map(|_| ())),
        "enableKerberosTrust" => Some(serde_json::from_value::<enable_kerberos_trust::Body>(value.clone()).map(|_| ())),
        "pairKerberosTrust" => Some(serde_json::from_value::<pair_kerberos_trust::Body>(value.clone()).map(|_| ())),
        "removeKerberosTrust" => Some(serde_json::from_value::<remove_kerberos_trust::Body>(value.clone()).map(|_| ())),
        "rotateKerberosTrustKey" => Some(serde_json::from_value::<rotate_kerberos_trust_key::Body>(value.clone()).map(|_| ())),
        "updateKerberosTrust" => Some(serde_json::from_value::<update_kerberos_trust::Body>(value.clone()).map(|_| ())),
        "clearEmailFactor" => Some(serde_json::from_value::<clear_email_factor::Body>(value.clone()).map(|_| ())),
        "clearSecurityKey" => Some(serde_json::from_value::<clear_security_key::Body>(value.clone()).map(|_| ())),
        "clearAuthenticatorApp" => Some(serde_json::from_value::<clear_authenticator_app::Body>(value.clone()).map(|_| ())),
        "recountPasskeyReport" => Some(serde_json::from_value::<recount_passkey_report::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getAuditExport", 200) => Some(serde_json::from_value::<get_audit_export::Answer200>(value.clone()).map(|_| ())),
        ("addAuditExportDestination", 200) => Some(serde_json::from_value::<add_audit_export_destination::Answer200>(value.clone()).map(|_| ())),
        ("disableAuditExportDestination", 200) => Some(serde_json::from_value::<disable_audit_export_destination::Answer200>(value.clone()).map(|_| ())),
        ("enableAuditExportDestination", 200) => Some(serde_json::from_value::<enable_audit_export_destination::Answer200>(value.clone()).map(|_| ())),
        ("removeAuditExportDestination", 200) => Some(serde_json::from_value::<remove_audit_export_destination::Answer200>(value.clone()).map(|_| ())),
        ("testAuditExportDestination", 200) => Some(serde_json::from_value::<test_audit_export_destination::Answer200>(value.clone()).map(|_| ())),
        ("updateAuditExportDestination", 200) => Some(serde_json::from_value::<update_audit_export_destination::Answer200>(value.clone()).map(|_| ())),
        ("getOutboundDeliveries", 200) => Some(serde_json::from_value::<get_outbound_deliveries::Answer200>(value.clone()).map(|_| ())),
        ("retryOutboundDelivery", 200) => Some(serde_json::from_value::<retry_outbound_delivery::Answer200>(value.clone()).map(|_| ())),
        ("getFederationRelationships", 200) => Some(serde_json::from_value::<get_federation_relationships::Answer200>(value.clone()).map(|_| ())),
        ("addFederationValue", 200) => Some(serde_json::from_value::<add_federation_value::Answer200>(value.clone()).map(|_| ())),
        ("checkFederationPartner", 200) => Some(serde_json::from_value::<check_federation_partner::Answer200>(value.clone()).map(|_| ())),
        ("createFederationRelationship", 200) => Some(serde_json::from_value::<create_federation_relationship::Answer200>(value.clone()).map(|_| ())),
        ("deleteFederationRelationship", 200) => Some(serde_json::from_value::<delete_federation_relationship::Answer200>(value.clone()).map(|_| ())),
        ("disableFederationRelationship", 200) => Some(serde_json::from_value::<disable_federation_relationship::Answer200>(value.clone()).map(|_| ())),
        ("enableFederationRelationship", 200) => Some(serde_json::from_value::<enable_federation_relationship::Answer200>(value.clone()).map(|_| ())),
        ("registerAtFederationPartner", 200) => Some(serde_json::from_value::<register_at_federation_partner::Answer200>(value.clone()).map(|_| ())),
        ("removeFederationValue", 200) => Some(serde_json::from_value::<remove_federation_value::Answer200>(value.clone()).map(|_| ())),
        ("rotateFederationKey", 200) => Some(serde_json::from_value::<rotate_federation_key::Answer200>(value.clone()).map(|_| ())),
        ("setFederationField", 200) => Some(serde_json::from_value::<set_federation_field::Answer200>(value.clone()).map(|_| ())),
        ("addFederationSignalsSubject", 200) => Some(serde_json::from_value::<add_federation_signals_subject::Answer200>(value.clone()).map(|_| ())),
        ("createFederationSignalsStream", 200) => Some(serde_json::from_value::<create_federation_signals_stream::Answer200>(value.clone()).map(|_| ())),
        ("deleteFederationSignalsStream", 200) => Some(serde_json::from_value::<delete_federation_signals_stream::Answer200>(value.clone()).map(|_| ())),
        ("discoverFederationSignals", 200) => Some(serde_json::from_value::<discover_federation_signals::Answer200>(value.clone()).map(|_| ())),
        ("pollFederationSignals", 200) => Some(serde_json::from_value::<poll_federation_signals::Answer200>(value.clone()).map(|_| ())),
        ("readFederationSignalsStatus", 200) => Some(serde_json::from_value::<read_federation_signals_status::Answer200>(value.clone()).map(|_| ())),
        ("readFederationSignalsStream", 200) => Some(serde_json::from_value::<read_federation_signals_stream::Answer200>(value.clone()).map(|_| ())),
        ("removeFederationSignalsSubject", 200) => Some(serde_json::from_value::<remove_federation_signals_subject::Answer200>(value.clone()).map(|_| ())),
        ("replaceFederationSignalsStream", 200) => Some(serde_json::from_value::<replace_federation_signals_stream::Answer200>(value.clone()).map(|_| ())),
        ("setFederationSignalsStatus", 200) => Some(serde_json::from_value::<set_federation_signals_status::Answer200>(value.clone()).map(|_| ())),
        ("unblockFederationSignals", 200) => Some(serde_json::from_value::<unblock_federation_signals::Answer200>(value.clone()).map(|_| ())),
        ("updateFederationSignalsStream", 200) => Some(serde_json::from_value::<update_federation_signals_stream::Answer200>(value.clone()).map(|_| ())),
        ("verifyFederationSignalsStream", 200) => Some(serde_json::from_value::<verify_federation_signals_stream::Answer200>(value.clone()).map(|_| ())),
        ("getGnap", 200) => Some(serde_json::from_value::<get_gnap::Answer200>(value.clone()).map(|_| ())),
        ("deleteGnapResourceSet", 200) => Some(serde_json::from_value::<delete_gnap_resource_set::Answer200>(value.clone()).map(|_| ())),
        ("getGnapMonitor", 200) => Some(serde_json::from_value::<get_gnap_monitor::Answer200>(value.clone()).map(|_| ())),
        ("revokeGnapGrant", 200) => Some(serde_json::from_value::<revoke_gnap_grant::Answer200>(value.clone()).map(|_| ())),
        ("getGroups", 200) => Some(serde_json::from_value::<get_groups::Answer200>(value.clone()).map(|_| ())),
        ("addGroupMember", 200) => Some(serde_json::from_value::<add_group_member::Answer200>(value.clone()).map(|_| ())),
        ("addGroupOwner", 200) => Some(serde_json::from_value::<add_group_owner::Answer200>(value.clone()).map(|_| ())),
        ("createGroup", 200) => Some(serde_json::from_value::<create_group::Answer200>(value.clone()).map(|_| ())),
        ("removeGroupOwner", 200) => Some(serde_json::from_value::<remove_group_owner::Answer200>(value.clone()).map(|_| ())),
        ("setGroupMail", 200) => Some(serde_json::from_value::<set_group_mail::Answer200>(value.clone()).map(|_| ())),
        ("setGroupPolicy", 200) => Some(serde_json::from_value::<set_group_policy::Answer200>(value.clone()).map(|_| ())),
        ("getKerberosSettings", 200) => Some(serde_json::from_value::<get_kerberos_settings::Answer200>(value.clone()).map(|_| ())),
        ("getKerberosPacClaims", 200) => Some(serde_json::from_value::<get_kerberos_pac_claims::Answer200>(value.clone()).map(|_| ())),
        ("addKerberosPacClaim", 200) => Some(serde_json::from_value::<add_kerberos_pac_claim::Answer200>(value.clone()).map(|_| ())),
        ("addKerberosPacAttributeClaim", 200) => Some(serde_json::from_value::<add_kerberos_pac_attribute_claim::Answer200>(value.clone()).map(|_| ())),
        ("setKerberosPacClaimAttributes", 200) => Some(serde_json::from_value::<set_kerberos_pac_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("selectAllKerberosPacClaimAttributes", 200) => Some(serde_json::from_value::<select_all_kerberos_pac_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearKerberosPacClaimAttributes", 200) => Some(serde_json::from_value::<clear_kerberos_pac_claim_attributes::Answer200>(value.clone()).map(|_| ())),
        ("clearKerberosPacClaims", 200) => Some(serde_json::from_value::<clear_kerberos_pac_claims::Answer200>(value.clone()).map(|_| ())),
        ("removeKerberosPacClaim", 200) => Some(serde_json::from_value::<remove_kerberos_pac_claim::Answer200>(value.clone()).map(|_| ())),
        ("replaceKerberosPacClaims", 200) => Some(serde_json::from_value::<replace_kerberos_pac_claims::Answer200>(value.clone()).map(|_| ())),
        ("getKerberosPrincipals", 200) => Some(serde_json::from_value::<get_kerberos_principals::Answer200>(value.clone()).map(|_| ())),
        ("clearKerberosPersonKeys", 200) => Some(serde_json::from_value::<clear_kerberos_person_keys::Answer200>(value.clone()).map(|_| ())),
        ("createKerberosServicePrincipal", 200) => Some(serde_json::from_value::<create_kerberos_service_principal::Answer200>(value.clone()).map(|_| ())),
        ("deleteKerberosServicePrincipal", 200) => Some(serde_json::from_value::<delete_kerberos_service_principal::Answer200>(value.clone()).map(|_| ())),
        ("dropKerberosPersonPreviousKeys", 200) => Some(serde_json::from_value::<drop_kerberos_person_previous_keys::Answer200>(value.clone()).map(|_| ())),
        ("dropKerberosServicePreviousKeys", 200) => Some(serde_json::from_value::<drop_kerberos_service_previous_keys::Answer200>(value.clone()).map(|_| ())),
        ("resetKerberosPersonKeytab", 200) => Some(serde_json::from_value::<reset_kerberos_person_keytab::Answer200>(value.clone()).map(|_| ())),
        ("rotateKerberosKrbtgt", 200) => Some(serde_json::from_value::<rotate_kerberos_krbtgt::Answer200>(value.clone()).map(|_| ())),
        ("rotateKerberosKrbtgtInvalidate", 200) => Some(serde_json::from_value::<rotate_kerberos_krbtgt_invalidate::Answer200>(value.clone()).map(|_| ())),
        ("rotateKerberosServicePrincipal", 200) => Some(serde_json::from_value::<rotate_kerberos_service_principal::Answer200>(value.clone()).map(|_| ())),
        ("getKerberosTrusts", 200) => Some(serde_json::from_value::<get_kerberos_trusts::Answer200>(value.clone()).map(|_| ())),
        ("addKerberosTrust", 200) => Some(serde_json::from_value::<add_kerberos_trust::Answer200>(value.clone()).map(|_| ())),
        ("disableKerberosTrust", 200) => Some(serde_json::from_value::<disable_kerberos_trust::Answer200>(value.clone()).map(|_| ())),
        ("enableKerberosTrust", 200) => Some(serde_json::from_value::<enable_kerberos_trust::Answer200>(value.clone()).map(|_| ())),
        ("pairKerberosTrust", 200) => Some(serde_json::from_value::<pair_kerberos_trust::Answer200>(value.clone()).map(|_| ())),
        ("removeKerberosTrust", 200) => Some(serde_json::from_value::<remove_kerberos_trust::Answer200>(value.clone()).map(|_| ())),
        ("rotateKerberosTrustKey", 200) => Some(serde_json::from_value::<rotate_kerberos_trust_key::Answer200>(value.clone()).map(|_| ())),
        ("updateKerberosTrust", 200) => Some(serde_json::from_value::<update_kerberos_trust::Answer200>(value.clone()).map(|_| ())),
        ("getLdapSettings", 200) => Some(serde_json::from_value::<get_ldap_settings::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryApplications", 200) => Some(serde_json::from_value::<get_directory_applications::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryDevices", 200) => Some(serde_json::from_value::<get_directory_devices::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryEntries", 200) => Some(serde_json::from_value::<get_directory_entries::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryFederations", 200) => Some(serde_json::from_value::<get_directory_federations::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryPeps", 200) => Some(serde_json::from_value::<get_directory_peps::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryPolicies", 200) => Some(serde_json::from_value::<get_directory_policies::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryRoles", 200) => Some(serde_json::from_value::<get_directory_roles::Answer200>(value.clone()).map(|_| ())),
        ("getDirectoryService", 200) => Some(serde_json::from_value::<get_directory_service::Answer200>(value.clone()).map(|_| ())),
        ("getDirectorySpiffe", 200) => Some(serde_json::from_value::<get_directory_spiffe::Answer200>(value.clone()).map(|_| ())),
        ("getMetrics", 200) => Some(serde_json::from_value::<get_metrics::Answer200>(value.clone()).map(|_| ())),
        ("getMultiFactor", 200) => Some(serde_json::from_value::<get_multi_factor::Answer200>(value.clone()).map(|_| ())),
        ("clearEmailFactor", 200) => Some(serde_json::from_value::<clear_email_factor::Answer200>(value.clone()).map(|_| ())),
        ("clearSecurityKey", 200) => Some(serde_json::from_value::<clear_security_key::Answer200>(value.clone()).map(|_| ())),
        ("clearAuthenticatorApp", 200) => Some(serde_json::from_value::<clear_authenticator_app::Answer200>(value.clone()).map(|_| ())),
        ("getPasskeyReport", 200) => Some(serde_json::from_value::<get_passkey_report::Answer200>(value.clone()).map(|_| ())),
        ("exportPasskeyAttestationEvidence", 200) => Some(serde_json::from_value::<export_passkey_attestation_evidence::Answer200>(value.clone()).map(|_| ())),
        ("exportPasskeyReport", 200) => Some(serde_json::from_value::<export_passkey_report::Answer200>(value.clone()).map(|_| ())),
        ("recountPasskeyReport", 200) => Some(serde_json::from_value::<recount_passkey_report::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
