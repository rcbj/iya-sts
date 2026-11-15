// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// What this API is, and every operation in it
pub mod get_index {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api";
    pub const OPERATION_ID: &str = "getIndex";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::ApiIndex;
}

/// The account API's OpenAPI document
pub mod get_account_api {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/account-api";
    pub const OPERATION_ID: &str = "getAccountApi";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        /// Where the account API publishes the document itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// Paths in the document.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<i64>,
        /// Operations in the document.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<sts_model_management_components_2::OpenApi2>,
    }
}

/// Every cache this service holds, or one cache's entries
pub mod get_caches {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/caches";
    pub const OPERATION_ID: &str = "getCaches";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cache: Option<String>,
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
        pub caches: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NotListedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OtherProcessesItemCachesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub size: Option<i64>,
        #[serde(rename = "largestRealm", default, skip_serializing_if = "Option::is_none")]
        pub largest_realm: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<i64>,
        #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub max_entries: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub hits: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub misses: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evictions: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refusals: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OtherProcessesItemTotals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evictions: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refusals: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200OtherProcessesItem {
        #[serde(rename = "nodeId", default, skip_serializing_if = "Option::is_none")]
        pub node_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<String>,
        #[serde(rename = "thisNode", default, skip_serializing_if = "Option::is_none")]
        pub this_node: Option<bool>,
        #[serde(rename = "takenAt", default, skip_serializing_if = "Option::is_none")]
        pub taken_at: Option<String>,
        #[serde(rename = "ageSeconds", default, skip_serializing_if = "Option::is_none")]
        pub age_seconds: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub caches: Option<Vec<Answer200OtherProcessesItemCachesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200OtherProcessesItemTotals>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EntriesItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub valid: Option<bool>,
        #[serde(rename = "validUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub valid_until: Option<Option<String>>,
        #[serde(rename = "remainingSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub remaining_seconds: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub basis: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remaining: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub caches: Option<Vec<sts_model_management_components_4::WithNameTitleDescription>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
        #[serde(rename = "notListed", default, skip_serializing_if = "Option::is_none")]
        pub not_listed: Option<Vec<Answer200NotListedItem>>,
        #[serde(rename = "otherProcesses", default, skip_serializing_if = "Option::is_none")]
        pub other_processes: Option<Vec<Answer200OtherProcessesItem>>,
        /// The one asked for by `?cache=`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cache: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        /// The caches there are, when the one asked for is not.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<sts_model_management_components_4::WithNameTitleDescription>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<Vec<Answer200EntriesItem>>,
        #[serde(rename = "entriesPaging", default, skip_serializing_if = "Option::is_none")]
        pub entries_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
    }
}

/// The cells of this service, the store's tiers and the channel between cells
pub mod get_cells {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/cells";
    pub const OPERATION_ID: &str = "getCells";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PeersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub jurisdiction: Option<Option<String>>,
        #[serde(rename = "consoleUrl", default, skip_serializing_if = "Option::is_none")]
        pub console_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reachable: Option<bool>,
        #[serde(rename = "answeredMs", default, skip_serializing_if = "Option::is_none")]
        pub answered_ms: Option<f64>,
        #[serde(rename = "reportedJurisdiction", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reported_jurisdiction: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StoreGlobalReplicationRetentionLastTrim {
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
    pub struct Answer200StoreGlobalReplicationRetention {
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
        pub last_trim: Option<Answer200StoreGlobalReplicationRetentionLastTrim>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StoreGlobalReplication {
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
        pub retention: Option<Answer200StoreGlobalReplicationRetention>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StoreRouting {
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
    pub struct Answer200StorePeoplePerCellItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Store {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tiered: Option<bool>,
        #[serde(rename = "globalReplicaLagMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub global_replica_lag_ms: Option<Option<f64>>,
        #[serde(rename = "globalReplication", default, skip_serializing_if = "Option::is_none")]
        pub global_replication: Option<Answer200StoreGlobalReplication>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub routing: Option<Answer200StoreRouting>,
        #[serde(rename = "peoplePerCell", default, skip_serializing_if = "Option::is_none")]
        pub people_per_cell: Option<Vec<Answer200StorePeoplePerCellItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ChannelCounters {
        #[serde(rename = "relayedOut", default, skip_serializing_if = "Option::is_none")]
        pub relayed_out: Option<i64>,
        #[serde(rename = "relayedIn", default, skip_serializing_if = "Option::is_none")]
        pub relayed_in: Option<i64>,
        #[serde(rename = "opsOut", default, skip_serializing_if = "Option::is_none")]
        pub ops_out: Option<i64>,
        #[serde(rename = "opsIn", default, skip_serializing_if = "Option::is_none")]
        pub ops_in: Option<i64>,
        #[serde(rename = "refusedPeers", default, skip_serializing_if = "Option::is_none")]
        pub refused_peers: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Channel {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listening: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub port: Option<Option<i64>>,
        #[serde(rename = "listenError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub listen_error: Option<Option<String>>,
        #[serde(rename = "certificateUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub certificate_until: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counters: Option<Answer200ChannelCounters>,
        #[serde(rename = "lastFailure", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_failure: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Placement {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relayed: Option<i64>,
        #[serde(rename = "placedHere", default, skip_serializing_if = "Option::is_none")]
        pub placed_here: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Sessions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub projections: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exports: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub multi: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub jurisdiction: Option<Option<String>>,
        #[serde(rename = "consoleUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub console_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peers: Option<Vec<Answer200PeersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<Answer200Store>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub channel: Option<Answer200Channel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub placement: Option<Answer200Placement>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sessions: Option<Answer200Sessions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub people: Option<sts_model_management_components_4::WithCellDescriptionRefused>,
    }
}

/// A page of another cell's residents, where its release policy permits
pub mod get_cell_people {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/cells/people";
    pub const OPERATION_ID: &str = "getCellPeople";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub cell: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub after: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithCellDescriptionRefused;
}

/// Move a person homed in this cell to another cell
pub mod rehome_person {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/cells/rehome";
    pub const OPERATION_ID: &str = "rehomePerson";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub username: String,
        pub target: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors4;
}

/// Every algorithm this service signs, verifies and encrypts with
pub mod get_crypto_metadata {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/crypto";
    pub const OPERATION_ID: &str = "getCryptoMetadata";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_1::CryptoMetadata;
}

/// Everything PostgreSQL reports about itself, and this service's schema in it
pub mod get_database {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/database";
    pub const OPERATION_ID: &str = "getDatabase";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TargetPasswordSecretProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TargetPasswordSecret {
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
        pub where_: Option<sts_model_management_components_4::WithFromSharedRegion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shared: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200TargetPasswordSecretProvidersItem>>,
    }

    /// Parsed out of the connection string, which is never returned.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Target {
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
        pub password_secret: Option<Answer200TargetPasswordSecret>,
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
    pub struct Answer200Pool {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub idle: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub waiting: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Derived {
        #[serde(rename = "cacheHitPercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cache_hit_percent: Option<Option<f64>>,
        #[serde(rename = "rollbackPercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub rollback_percent: Option<Option<f64>>,
        #[serde(rename = "deadTuplePercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dead_tuple_percent: Option<Option<f64>>,
        #[serde(rename = "unusedIndexes", default, skip_serializing_if = "Option::is_none")]
        pub unused_indexes: Option<Vec<String>>,
        #[serde(rename = "seqScans", default, skip_serializing_if = "Option::is_none")]
        pub seq_scans: Option<f64>,
        #[serde(rename = "idxScans", default, skip_serializing_if = "Option::is_none")]
        pub idx_scans: Option<f64>,
        #[serde(rename = "statsReset", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub stats_reset: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SchemaExpected {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub version: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SchemaDrift {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub declared: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        /// Parsed out of the connection string, which is never returned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<Answer200Target>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pool: Option<Answer200Pool>,
        #[serde(rename = "tookMs", default, skip_serializing_if = "Option::is_none")]
        pub took_ms: Option<f64>,
        #[serde(rename = "statementTimeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub statement_timeout_ms: Option<f64>,
        #[serde(rename = "statementTimeoutSet", default, skip_serializing_if = "Option::is_none")]
        pub statement_timeout_set: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        /// One answer per probe, by its id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub probes: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub schema: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub derived: Option<Answer200Derived>,
        #[serde(rename = "schemaExpected", default, skip_serializing_if = "Option::is_none")]
        pub schema_expected: Option<Answer200SchemaExpected>,
        #[serde(rename = "schemaDrift", default, skip_serializing_if = "Option::is_none")]
        pub schema_drift: Option<Answer200SchemaDrift>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<Vec<String>>,
    }
}

/// Whether the identity protocol debugger is embedded, where it answers, and
/// what its api process is doing
pub mod get_debugger {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/debugger";
    pub const OPERATION_ID: &str = "getDebugger";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApiLastExit {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub code: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub signal: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(rename = "upSeconds", default, skip_serializing_if = "Option::is_none")]
        pub up_seconds: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Api {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub socket: Option<Option<String>>,
        #[serde(rename = "apiDirectory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub api_directory: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub starts: Option<i64>,
        #[serde(rename = "consecutiveFailures", default, skip_serializing_if = "Option::is_none")]
        pub consecutive_failures: Option<i64>,
        #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub started_at: Option<Option<String>>,
        #[serde(rename = "listeningAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub listening_at: Option<Option<String>>,
        #[serde(rename = "lastExit", default, skip_serializing_if = "Option::is_none")]
        pub last_exit: Option<Answer200ApiLastExit>,
        #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_error: Option<Option<String>>,
        #[serde(rename = "uiUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ui_url: Option<Option<String>>,
        #[serde(rename = "allowList", default, skip_serializing_if = "Option::is_none")]
        pub allow_list: Option<bool>,
        #[serde(rename = "allowedRanges", default, skip_serializing_if = "Option::is_none")]
        pub allowed_ranges: Option<Vec<String>>,
        #[serde(rename = "allowListProblems", default, skip_serializing_if = "Option::is_none")]
        pub allow_list_problems: Option<Vec<String>>,
        #[serde(rename = "anchorReplacements", default, skip_serializing_if = "Option::is_none")]
        pub anchor_replacements: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub embedded: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub started: Option<bool>,
        #[serde(rename = "startProblem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub start_problem: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listening: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<f64>,
        #[serde(rename = "listenError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub listen_error: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scheme: Option<String>,
        #[serde(rename = "publicBaseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub public_base_url: Option<Option<String>>,
        #[serde(rename = "uiDirectory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ui_directory: Option<Option<String>>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub api: Option<Answer200Api>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
    }
}

/// What this service encrypts at rest, and how much of it it has done
pub mod get_encryption {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/encryption";
    pub const OPERATION_ID: &str = "getEncryption";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "dataKeysPage", default, skip_serializing_if = "Option::is_none")]
        pub data_keys_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeyProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Key {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub present: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persists: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ephemeral: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(rename = "providerLabel", default, skip_serializing_if = "Option::is_none")]
        pub provider_label: Option<String>,
        #[serde(rename = "inKms", default, skip_serializing_if = "Option::is_none")]
        pub in_kms: Option<bool>,
        #[serde(rename = "kmsKey", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kms_key: Option<Option<String>>,
        #[serde(rename = "providerKnown", default, skip_serializing_if = "Option::is_none")]
        pub provider_known: Option<bool>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<sts_model_management_components_4::WithFromSharedRegion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200KeyProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Algorithm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub envelope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<sts_model_base::unions::NumberOrString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cipher: Option<String>,
        #[serde(rename = "keyBits", default, skip_serializing_if = "Option::is_none")]
        pub key_bits: Option<i64>,
        #[serde(rename = "ivBits", default, skip_serializing_if = "Option::is_none")]
        pub iv_bits: Option<i64>,
        #[serde(rename = "tagBits", default, skip_serializing_if = "Option::is_none")]
        pub tag_bits: Option<i64>,
        #[serde(rename = "dataKeys", default, skip_serializing_if = "Option::is_none")]
        pub data_keys: Option<String>,
        #[serde(rename = "dataCiphers", default, skip_serializing_if = "Option::is_none")]
        pub data_ciphers: Option<Vec<String>>,
        #[serde(rename = "dekWrap", default, skip_serializing_if = "Option::is_none")]
        pub dek_wrap: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aad: Option<String>,
        #[serde(rename = "perRecordSubkey", default, skip_serializing_if = "Option::is_none")]
        pub per_record_subkey: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DataKeysLifecycle {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<bool>,
        #[serde(rename = "offReason", default, skip_serializing_if = "Option::is_none")]
        pub off_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scheduled: Option<bool>,
        #[serde(rename = "scheduleOffReason", default, skip_serializing_if = "Option::is_none")]
        pub schedule_off_reason: Option<String>,
        #[serde(rename = "rotationDays", default, skip_serializing_if = "Option::is_none")]
        pub rotation_days: Option<f64>,
        #[serde(rename = "activationLeadSeconds", default, skip_serializing_if = "Option::is_none")]
        pub activation_lead_seconds: Option<f64>,
        #[serde(rename = "retireAfterDays", default, skip_serializing_if = "Option::is_none")]
        pub retire_after_days: Option<f64>,
        #[serde(rename = "directoryCipher", default, skip_serializing_if = "Option::is_none")]
        pub directory_cipher: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counting: Option<bool>,
        #[serde(rename = "countOffReason", default, skip_serializing_if = "Option::is_none")]
        pub count_off_reason: Option<String>,
        #[serde(rename = "kekRotation", default, skip_serializing_if = "Option::is_none")]
        pub kek_rotation: Option<bool>,
        #[serde(rename = "kekRotationOffReason", default, skip_serializing_if = "Option::is_none")]
        pub kek_rotation_off_reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jobs: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DataKeysCounts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub superseded: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destroyed: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub derived: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DataKeysKeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cls: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub scope: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<String>>,
        #[serde(rename = "activateAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub activate_at: Option<Option<String>>,
        #[serde(rename = "ageDays", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub age_days: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub values: Option<Option<f64>>,
        #[serde(rename = "countedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub counted_at: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DataKeys {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lifecycle: Option<Answer200DataKeysLifecycle>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200DataKeysCounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(rename = "lastCounted", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_counted: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200DataKeysKeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Boundaries {
        #[serde(rename = "perRealmKey", default, skip_serializing_if = "Option::is_none")]
        pub per_realm_key: Option<bool>,
        #[serde(rename = "perRealmDataKey", default, skip_serializing_if = "Option::is_none")]
        pub per_realm_data_key: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realms: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub storage: Option<String>,
        #[serde(rename = "keyResidency", default, skip_serializing_if = "Option::is_none")]
        pub key_residency: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Store {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "configuredMode", default, skip_serializing_if = "Option::is_none")]
        pub configured_mode: Option<String>,
        #[serde(rename = "fellBack", default, skip_serializing_if = "Option::is_none")]
        pub fell_back: Option<bool>,
        #[serde(rename = "persistsMinted", default, skip_serializing_if = "Option::is_none")]
        pub persists_minted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClassesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sealed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub encryptions: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub decryptions: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub failures: Option<Option<i64>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Accounting {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub encryptions: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decryptions: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<i64>,
        #[serde(rename = "plaintextBytes", default, skip_serializing_if = "Option::is_none")]
        pub plaintext_bytes: Option<f64>,
        #[serde(rename = "ciphertextBytes", default, skip_serializing_if = "Option::is_none")]
        pub ciphertext_bytes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
        #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub first_at: Option<Option<String>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub labels: Option<sts_model_management_components_4::WithOkMessageErrors2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<Answer200Key>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<Answer200Algorithm>,
        #[serde(rename = "dataKeys", default, skip_serializing_if = "Option::is_none")]
        pub data_keys: Option<Answer200DataKeys>,
        #[serde(rename = "algorithmNote", default, skip_serializing_if = "Option::is_none")]
        pub algorithm_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub boundaries: Option<Answer200Boundaries>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<Answer200Store>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub classes: Option<Vec<Answer200ClassesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unclassified: Option<sts_model_management_components_4::WithOkMessageErrors2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounting: Option<Answer200Accounting>,
        #[serde(rename = "accountingNote", default, skip_serializing_if = "Option::is_none")]
        pub accounting_note: Option<String>,
        #[serde(rename = "failuresNote", default, skip_serializing_if = "Option::is_none")]
        pub failures_note: Option<String>,
        #[serde(rename = "noSamples", default, skip_serializing_if = "Option::is_none")]
        pub no_samples: Option<String>,
    }
}

/// Count what is sealed under every data key now
pub mod count_data_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/encryption/count-data-keys";
    pub const OPERATION_ID: &str = "countDataKeys";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors3;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors3;
}

/// Run the data re-encryption pass now
pub mod reencrypt_data_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/encryption/reencrypt-data-keys";
    pub const OPERATION_ID: &str = "reencryptDataKeys";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors3;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors3;
}

/// Rotate the data encryption keys now
pub mod rotate_data_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/encryption/rotate-data-keys";
    pub const OPERATION_ID: &str = "rotateDataKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A realm id; omitted for every realm, `default` for the default realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        /// A data class, e.g. `minted-rows`; omitted for every class.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cls: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors3;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors3;
}

/// Rotate the key-encryption key in its key management service
pub mod rotate_kek {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/encryption/rotate-kek";
    pub const OPERATION_ID: &str = "rotateKek";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors3;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors3;
}

/// Every key pair this process generated at start, and what it is for
pub mod get_keys {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/keys";
    pub const OPERATION_ID: &str = "getKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::KeyList;
}

/// Rotate the realm's signing keys in an EMERGENCY
pub mod rotate_signing_keys_emergency {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/keys/emergency";
    pub const OPERATION_ID: &str = "rotateSigningKeysEmergency";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub confirm: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub units: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors16;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors16;
}

/// Hand over one key pair, in a chosen keystore format
pub mod export_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/keys/export";
    pub const OPERATION_ID: &str = "exportKey";

    /// PKCS#12 is offered only for a key this service holds a certificate for — the
    /// signing key and the TLS key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyFormat {
        #[serde(rename = "pem")]
        Pem,
        #[serde(rename = "der")]
        Der,
        #[serde(rename = "jwk")]
        Jwk,
        #[serde(rename = "pkcs12")]
        Pkcs12,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The `id` from GET /admin-api/keys.
        pub key: String,
        /// PKCS#12 is offered only for a key this service holds a certificate for —
        /// the signing key and the TLS key.
        pub format: BodyFormat,
        /// REQUIRED for `pkcs12`; optional for the other three, where it encrypts
        /// the private half. Empty means the private key comes out in the clear.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::KeyExport;
}

/// Every signing key this realm has ever held
pub mod get_key_history {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/keys/history";
    pub const OPERATION_ID: &str = "getKeyHistory";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200UnitsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unit: Option<String>,
        #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub use_case: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub slot: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generations: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub live: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dropped: Option<i64>,
        #[serde(rename = "withCertificate", default, skip_serializing_if = "Option::is_none")]
        pub with_certificate: Option<i64>,
        #[serde(rename = "newestAt", default, skip_serializing_if = "Option::is_none")]
        pub newest_at: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemCertificate {
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
        pub signature_alg: Option<String>,
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
        #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
        pub chain_pem: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unit: Option<String>,
        #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub use_case: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub slot: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub crv: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kind: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub role: Option<Option<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<String>>,
        #[serde(rename = "firstSeenAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub first_seen_at: Option<Option<String>>,
        #[serde(rename = "promotedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub promoted_at: Option<Option<String>>,
        #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub retired_at: Option<Option<String>>,
        #[serde(rename = "verifiesUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub verifies_until: Option<Option<String>>,
        #[serde(rename = "droppedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub dropped_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Answer200RowsItemCertificate>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub units: Option<Vec<Answer200UnitsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub observed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_2::PagingValue>,
    }
}

/// One signing key's certificate chain, as PEM
pub mod get_key_history_certificate {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/keys/history/certificate";
    pub const OPERATION_ID: &str = "getKeyHistoryCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub unit: String,
        pub kid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }
}

/// Rotate the realm's signing keys now
pub mod rotate_signing_keys {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/keys/rotate";
    pub const OPERATION_ID: &str = "rotateSigningKeys";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Units from GET /admin-api/keys `rotation.units`, e.g. `jose:RS256`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub units: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors16;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors16;
}

/// Every listener, its TLS policy and client authentication, and which hosted
/// application is on which
pub mod get_listeners {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/listeners";
    pub const OPERATION_ID: &str = "getListeners";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListenersItemPolicyTls13SuitesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
        pub post_quantum: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListenersItemPolicy {
        #[serde(rename = "minVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub min_version: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls12: Option<bool>,
        #[serde(rename = "tls13Suites", default, skip_serializing_if = "Option::is_none")]
        pub tls13_suites: Option<Vec<Answer200ListenersItemPolicyTls13SuitesItem>>,
        #[serde(rename = "tls12Ciphers", default, skip_serializing_if = "Option::is_none")]
        pub tls12_ciphers: Option<Vec<String>>,
        #[serde(rename = "pqcOnly", default, skip_serializing_if = "Option::is_none")]
        pub pqc_only: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<String>,
        #[serde(rename = "signatureAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub signature_algorithms: Option<String>,
        #[serde(rename = "sessionTimeoutS", default, skip_serializing_if = "Option::is_none")]
        pub session_timeout_s: Option<f64>,
        #[serde(rename = "sessionCacheSize", default, skip_serializing_if = "Option::is_none")]
        pub session_cache_size: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub truststore: Option<String>,
        #[serde(rename = "clientAuth", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_auth: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListenersItemHttp {
        #[serde(rename = "keepAliveTimeoutS", default, skip_serializing_if = "Option::is_none")]
        pub keep_alive_timeout_s: Option<f64>,
        #[serde(rename = "headersTimeoutS", default, skip_serializing_if = "Option::is_none")]
        pub headers_timeout_s: Option<f64>,
        #[serde(rename = "maxRequestsPerSocket", default, skip_serializing_if = "Option::is_none")]
        pub max_requests_per_socket: Option<f64>,
        #[serde(rename = "maxConnections", default, skip_serializing_if = "Option::is_none")]
        pub max_connections: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http2: Option<bool>,
        #[serde(rename = "http2MaxConcurrentStreams", default, skip_serializing_if = "Option::is_none")]
        pub http2_max_concurrent_streams: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListenersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub port: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub group: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Answer200ListenersItemPolicy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http: Option<Answer200ListenersItemHttp>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CustomItemCertificate {
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
    pub struct Answer200CustomItemHttp {
        #[serde(rename = "keepAliveTimeoutS", default, skip_serializing_if = "Option::is_none")]
        pub keep_alive_timeout_s: Option<f64>,
        #[serde(rename = "headersTimeoutS", default, skip_serializing_if = "Option::is_none")]
        pub headers_timeout_s: Option<f64>,
        #[serde(rename = "maxRequestsPerSocket", default, skip_serializing_if = "Option::is_none")]
        pub max_requests_per_socket: Option<f64>,
        #[serde(rename = "maxConnections", default, skip_serializing_if = "Option::is_none")]
        pub max_connections: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http2: Option<bool>,
        #[serde(rename = "http2MaxConcurrentStreams", default, skip_serializing_if = "Option::is_none")]
        pub http2_max_concurrent_streams: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CustomItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
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
        /// A listener's own TLS values, per setting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Answer200CustomItemCertificate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<sts_model_management_components_4::WithMinVersionTls12Tls13Suites>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http: Option<Answer200CustomItemHttp>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ApplicationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listeners: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub advertised: Option<Option<String>>,
        #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
        pub decided_by: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Definitions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listeners: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<String>,
        #[serde(rename = "serviceApplications", default, skip_serializing_if = "Option::is_none")]
        pub service_applications: Option<String>,
        #[serde(rename = "cookieDomain", default, skip_serializing_if = "Option::is_none")]
        pub cookie_domain: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Problem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LiveItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listeners: Option<Vec<Answer200ListenersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub custom: Option<Vec<Answer200CustomItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applications: Option<Vec<Answer200ApplicationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub definitions: Option<Answer200Definitions>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rescue: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<Answer200Problem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub warnings: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process: Option<sts_model_management_components_4::WithMinVersionTls12Tls13Suites>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub live: Option<Vec<Answer200LiveItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
    }
}

/// Map hosted applications to listeners
pub mod set_listener_applications {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/listeners/set-applications";
    pub const OPERATION_ID: &str = "setListenerApplications";

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
        /// The mapping: a JSON object, as text or as the object.
        pub value: sts_model_base::unions::StringOrObject,
        /// Take the management API off the listener this call arrived on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<BodyConfirm>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors6;
}

/// Replace the custom listeners this realm defines
pub mod set_listeners {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/listeners/set-listeners";
    pub const OPERATION_ID: &str = "setListeners";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyValue {
        V1(Vec<serde_json::Value>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The listeners: a JSON array, as text or as the array.
        pub value: BodyValue,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors6;
}

/// The mail channel in this realm: its transport, its messages, its settings
pub mod get_mail {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/mail";
    pub const OPERATION_ID: &str = "getMail";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryTemplate {
        #[serde(rename = "password-reset")]
        PasswordReset,
        #[serde(rename = "account-activation")]
        AccountActivation,
        #[serde(rename = "address-verification")]
        AddressVerification,
        #[serde(rename = "pseudonym-verification")]
        PseudonymVerification,
        #[serde(rename = "password-changed")]
        PasswordChanged,
        #[serde(rename = "account-disabled")]
        AccountDisabled,
        #[serde(rename = "sessions-ended")]
        SessionsEnded,
        #[serde(rename = "credential-compromised")]
        CredentialCompromised,
        #[serde(rename = "recovery-started")]
        RecoveryStarted,
        #[serde(rename = "address-changed")]
        AddressChanged,
        #[serde(rename = "account-connected")]
        AccountConnected,
        #[serde(rename = "access-request")]
        AccessRequest,
        #[serde(rename = "uma-approval")]
        UmaApproval,
        #[serde(rename = "authzen-access-request")]
        AuthzenAccessRequest,
        #[serde(rename = "authzen-emergency-access")]
        AuthzenEmergencyAccess,
        #[serde(rename = "pki-pin-status")]
        PkiPinStatus,
        #[serde(rename = "administrator-alert")]
        AdministratorAlert,
        #[serde(rename = "sign-in-code")]
        SignInCode,
        #[serde(rename = "sign-in-link")]
        SignInLink,
        #[serde(rename = "report-ready")]
        ReportReady,
        #[serde(rename = "post-login-reminder")]
        PostLoginReminder,
        #[serde(rename = "reset-refused-attempt")]
        ResetRefusedAttempt,
        #[serde(rename = "layout")]
        Layout,
        #[serde(rename = "test-message")]
        TestMessage,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub template: Option<QueryTemplate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lang: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Relay {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub host: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub port: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub tls: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub auth: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dkim: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200BuildProblem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sent: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub captured: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dead: Option<i64>,
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
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TemplatesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub languages: Option<Vec<String>>,
        #[serde(rename = "builtInLanguages", default, skip_serializing_if = "Option::is_none")]
        pub built_in_languages: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Template {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lang: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub own: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub html: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub setting: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub transport: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub from: Option<Option<String>>,
        #[serde(rename = "linkBase", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub link_base: Option<Option<String>>,
        #[serde(rename = "linkBasePinned", default, skip_serializing_if = "Option::is_none")]
        pub link_base_pinned: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relay: Option<Answer200Relay>,
        #[serde(rename = "buildProblem", default, skip_serializing_if = "Option::is_none")]
        pub build_problem: Option<Answer200BuildProblem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub categories: Option<Vec<Answer200CategoriesItem>>,
        #[serde(rename = "selfServiceReset", default, skip_serializing_if = "Option::is_none")]
        pub self_service_reset: Option<bool>,
        #[serde(rename = "securityNotices", default, skip_serializing_if = "Option::is_none")]
        pub security_notices: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub templates: Option<Vec<Answer200TemplatesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub template: Option<Answer200Template>,
    }
}

/// Every message this realm queued, and what became of it
pub mod get_mail_outbox {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/mail/outbox";
    pub const OPERATION_ID: &str = "getMailOutbox";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryState {
        #[serde(rename = "pending")]
        Pending,
        #[serde(rename = "sent")]
        Sent,
        #[serde(rename = "captured")]
        Captured,
        #[serde(rename = "dead")]
        Dead,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<QueryState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
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
        pub pending: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sent: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub captured: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dead: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub to: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub category: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub template: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub lang: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub from: Option<Option<String>>,
        #[serde(rename = "messageId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub message_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub via: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub actor: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub transport: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attempts: Option<f64>,
        #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
        pub in_flight: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
        #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub error_code: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
        #[serde(rename = "providerId", default, skip_serializing_if = "Option::is_none")]
        pub provider_id: Option<String>,
        #[serde(rename = "bodyKept", default, skip_serializing_if = "Option::is_none")]
        pub body_kept: Option<bool>,
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
        pub queued_at: Option<String>,
        #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub next_attempt_at: Option<String>,
        #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub last_attempt_at: Option<String>,
        #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
        pub finished_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub text: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub html: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Message {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub username: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub to: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub category: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub template: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub lang: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub from: Option<Option<String>>,
        #[serde(rename = "messageId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub message_id: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub via: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub actor: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub transport: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attempts: Option<f64>,
        #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
        pub in_flight: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
        #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub error_code: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub why: Option<Option<String>>,
        #[serde(rename = "providerId", default, skip_serializing_if = "Option::is_none")]
        pub provider_id: Option<String>,
        #[serde(rename = "bodyKept", default, skip_serializing_if = "Option::is_none")]
        pub body_kept: Option<bool>,
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
        pub queued_at: Option<String>,
        #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub next_attempt_at: Option<String>,
        #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub last_attempt_at: Option<String>,
        #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
        pub finished_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub text: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub html: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub transport: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(rename = "rowsPaging", default, skip_serializing_if = "Option::is_none")]
        pub rows_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<Answer200Message>,
    }
}

/// Send a dead letter again
pub mod retry_mail_dead_letter {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mail/outbox/retry";
    pub const OPERATION_ID: &str = "retryMailDeadLetter";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The message id, as the outbox lists it.
        pub message: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors9;
}

/// Put a message back to the built-in wording
pub mod reset_mail_template {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mail/reset-template";
    pub const OPERATION_ID: &str = "resetMailTemplate";

    /// The message id.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTemplate {
        #[serde(rename = "password-reset")]
        PasswordReset,
        #[serde(rename = "account-activation")]
        AccountActivation,
        #[serde(rename = "address-verification")]
        AddressVerification,
        #[serde(rename = "pseudonym-verification")]
        PseudonymVerification,
        #[serde(rename = "password-changed")]
        PasswordChanged,
        #[serde(rename = "account-disabled")]
        AccountDisabled,
        #[serde(rename = "sessions-ended")]
        SessionsEnded,
        #[serde(rename = "credential-compromised")]
        CredentialCompromised,
        #[serde(rename = "recovery-started")]
        RecoveryStarted,
        #[serde(rename = "address-changed")]
        AddressChanged,
        #[serde(rename = "account-connected")]
        AccountConnected,
        #[serde(rename = "access-request")]
        AccessRequest,
        #[serde(rename = "uma-approval")]
        UmaApproval,
        #[serde(rename = "authzen-access-request")]
        AuthzenAccessRequest,
        #[serde(rename = "authzen-emergency-access")]
        AuthzenEmergencyAccess,
        #[serde(rename = "pki-pin-status")]
        PkiPinStatus,
        #[serde(rename = "administrator-alert")]
        AdministratorAlert,
        #[serde(rename = "sign-in-code")]
        SignInCode,
        #[serde(rename = "sign-in-link")]
        SignInLink,
        #[serde(rename = "report-ready")]
        ReportReady,
        #[serde(rename = "post-login-reminder")]
        PostLoginReminder,
        #[serde(rename = "reset-refused-attempt")]
        ResetRefusedAttempt,
        #[serde(rename = "layout")]
        Layout,
        #[serde(rename = "test-message")]
        TestMessage,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The message id.
        pub template: BodyTemplate,
        /// A BCP 47 tag.
        pub lang: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors9;
}

/// Save this realm's wording of a message in a language
pub mod save_mail_template {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mail/save-template";
    pub const OPERATION_ID: &str = "saveMailTemplate";

    /// The message id.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTemplate {
        #[serde(rename = "password-reset")]
        PasswordReset,
        #[serde(rename = "account-activation")]
        AccountActivation,
        #[serde(rename = "address-verification")]
        AddressVerification,
        #[serde(rename = "pseudonym-verification")]
        PseudonymVerification,
        #[serde(rename = "password-changed")]
        PasswordChanged,
        #[serde(rename = "account-disabled")]
        AccountDisabled,
        #[serde(rename = "sessions-ended")]
        SessionsEnded,
        #[serde(rename = "credential-compromised")]
        CredentialCompromised,
        #[serde(rename = "recovery-started")]
        RecoveryStarted,
        #[serde(rename = "address-changed")]
        AddressChanged,
        #[serde(rename = "account-connected")]
        AccountConnected,
        #[serde(rename = "access-request")]
        AccessRequest,
        #[serde(rename = "uma-approval")]
        UmaApproval,
        #[serde(rename = "authzen-access-request")]
        AuthzenAccessRequest,
        #[serde(rename = "authzen-emergency-access")]
        AuthzenEmergencyAccess,
        #[serde(rename = "pki-pin-status")]
        PkiPinStatus,
        #[serde(rename = "administrator-alert")]
        AdministratorAlert,
        #[serde(rename = "sign-in-code")]
        SignInCode,
        #[serde(rename = "sign-in-link")]
        SignInLink,
        #[serde(rename = "report-ready")]
        ReportReady,
        #[serde(rename = "post-login-reminder")]
        PostLoginReminder,
        #[serde(rename = "reset-refused-attempt")]
        ResetRefusedAttempt,
        #[serde(rename = "layout")]
        Layout,
        #[serde(rename = "test-message")]
        TestMessage,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The message id.
        pub template: BodyTemplate,
        /// A BCP 47 tag.
        pub lang: String,
        /// One line.
        pub subject: String,
        /// The text part.
        pub text: String,
        /// The HTML part.
        pub html: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors9;
}

/// Send a test message to a person in this realm
pub mod send_mail_test_message {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mail/test";
    pub const OPERATION_ID: &str = "sendMailTestMessage";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, by username.
        pub user: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors9;
}

/// Mail a person a link that verifies their address
pub mod send_mail_verification_link {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/mail/verify";
    pub const OPERATION_ID: &str = "sendMailVerificationLink";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The person, by username.
        pub user: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors9;
}

/// Whether uploaded files are scanned, and by which ICAP service
pub mod get_malware_scanning {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/malware-scanning";
    pub const OPERATION_ID: &str = "getMalwareScanning";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub enabled: bool,
        pub url: String,
        pub scanning: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
    }
}

/// Check that the configured ICAP service really scans
pub mod test_malware_scanning {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/malware-scanning/test";
    pub const OPERATION_ID: &str = "testMalwareScanning";

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

/// Who the caller is here, and what they may do
pub mod get_me {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/me";
    pub const OPERATION_ID: &str = "getMe";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Caller {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_id: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ConsoleBootstrap {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seeded: Option<bool>,
        #[serde(rename = "claimedAt", default, skip_serializing_if = "Option::is_none")]
        pub claimed_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Console {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub available: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub open: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub empty: Option<bool>,
        #[serde(rename = "windowOpens", default, skip_serializing_if = "Option::is_none")]
        pub window_opens: Option<bool>,
        #[serde(rename = "bootstrapPasswordRequired", default, skip_serializing_if = "Option::is_none")]
        pub bootstrap_password_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bootstrap: Option<Answer200ConsoleBootstrap>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        /// Whether this API requires an access token, in force.
        #[serde(rename = "tokenRequired", default, skip_serializing_if = "Option::is_none")]
        pub token_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub caller: Option<Answer200Caller>,
        /// The realm the caller belongs to: the one that issued the token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        /// The realm this request was read in.
        #[serde(rename = "readingRealm", default, skip_serializing_if = "Option::is_none")]
        pub reading_realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub authority: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub read: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub write: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub security: Option<bool>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<f64>>,
        /// This person's photo on this realm, empty where they have none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub photo: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "readGroup", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub read_group: Option<Option<String>>,
        #[serde(rename = "writeGroup", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub write_group: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub console: Option<Answer200Console>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<Vec<String>>,
    }
}

/// What global.mode changes, and what is in force in this realm
pub mod get_mode {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/mode";
    pub const OPERATION_ID: &str = "getMode";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200RequirementsItemWaivedItemDynamicRegistrationValue {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RequirementsItemWaivedItemDynamicRegistration {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<Answer200RequirementsItemWaivedItemDynamicRegistrationValue>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RequirementsItemWaivedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requirement: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub section: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(rename = "perApplication", default, skip_serializing_if = "Option::is_none")]
        pub per_application: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attribute: Option<String>,
        #[serde(rename = "dynamicRegistration", default, skip_serializing_if = "Option::is_none")]
        pub dynamic_registration: Option<Answer200RequirementsItemWaivedItemDynamicRegistration>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RequirementsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "inForce", default, skip_serializing_if = "Option::is_none")]
        pub in_force: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub development: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub product: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub waived: Option<Vec<Answer200RequirementsItemWaivedItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200DevelopmentOnlySettingsItemDefault {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200DevelopmentOnlySettingsItemValue {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200DevelopmentOnlySettingsItemInForce {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DevelopmentOnlySettingsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub predicate: Option<String>,
        #[serde(rename = "developmentOnlyValues", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub development_only_values: Option<Option<Vec<serde_json::Value>>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default: Option<Option<Answer200DevelopmentOnlySettingsItemDefault>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<Answer200DevelopmentOnlySettingsItemValue>>,
        #[serde(rename = "inForce", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub in_force: Option<Option<Answer200DevelopmentOnlySettingsItemInForce>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ignored: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NotYetItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "isProduct", default, skip_serializing_if = "Option::is_none")]
        pub is_product: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requirements: Option<Vec<Answer200RequirementsItem>>,
        #[serde(rename = "developmentOnlySettings", default, skip_serializing_if = "Option::is_none")]
        pub development_only_settings: Option<Vec<Answer200DevelopmentOnlySettingsItem>>,
        #[serde(rename = "notYet", default, skip_serializing_if = "Option::is_none")]
        pub not_yet: Option<Vec<Answer200NotYetItem>>,
    }
}

/// The CPU and memory of this node's container, and the Node.js memory of each
/// of its processes and worker threads
pub mod get_node_health {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/node-health";
    pub const OPERATION_ID: &str = "getNodeHealth";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Machine {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub loadavg: Option<Vec<f64>>,
        #[serde(rename = "totalmemBytes", default, skip_serializing_if = "Option::is_none")]
        pub totalmem_bytes: Option<f64>,
        #[serde(rename = "freememBytes", default, skip_serializing_if = "Option::is_none")]
        pub freemem_bytes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cpus: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AnsweredBy {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NodesItemViewMachine {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub loadavg: Option<Vec<f64>>,
        #[serde(rename = "totalmemBytes", default, skip_serializing_if = "Option::is_none")]
        pub totalmem_bytes: Option<f64>,
        #[serde(rename = "freememBytes", default, skip_serializing_if = "Option::is_none")]
        pub freemem_bytes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cpus: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NodesItemView {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(rename = "scopeText", default, skip_serializing_if = "Option::is_none")]
        pub scope_text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cgroup: Option<Option<String>>,
        #[serde(rename = "cgroupVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cgroup_version: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cpu: Option<sts_model_management_components_4::WithAvailableFromEcsCgroupVersion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub memory: Option<sts_model_management_components_4::WithAvailableFromEcsCgroupVersion2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<sts_model_management_components_4::WithRowsUnansweredDebuggerNote>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ecs: Option<sts_model_management_components_4::WithAvailableEndpointDockerId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub machine: Option<Answer200NodesItemViewMachine>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NodesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
        pub self_: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "stateText", default, skip_serializing_if = "Option::is_none")]
        pub state_text: Option<String>,
        #[serde(rename = "ageSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub age_seconds: Option<Option<f64>>,
        #[serde(rename = "takenAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub taken_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200NodesItemView>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Totals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<i64>,
        #[serde(rename = "nodesCounted", default, skip_serializing_if = "Option::is_none")]
        pub nodes_counted: Option<i64>,
        #[serde(rename = "memoryNodes", default, skip_serializing_if = "Option::is_none")]
        pub memory_nodes: Option<i64>,
        #[serde(rename = "memoryUsedBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub memory_used_bytes: Option<Option<f64>>,
        #[serde(rename = "memoryLimitBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub memory_limit_bytes: Option<Option<f64>>,
        #[serde(rename = "memoryPercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub memory_percent: Option<Option<f64>>,
        #[serde(rename = "cpuNodes", default, skip_serializing_if = "Option::is_none")]
        pub cpu_nodes: Option<i64>,
        #[serde(rename = "cpuCoresUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cpu_cores_used: Option<Option<f64>>,
        #[serde(rename = "cpuOf", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cpu_of: Option<Option<f64>>,
        #[serde(rename = "cpuPercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cpu_percent: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<i64>,
        #[serde(rename = "workerThreads", default, skip_serializing_if = "Option::is_none")]
        pub worker_threads: Option<i64>,
        #[serde(rename = "rssBytes", default, skip_serializing_if = "Option::is_none")]
        pub rss_bytes: Option<f64>,
        #[serde(rename = "heapUsedBytes", default, skip_serializing_if = "Option::is_none")]
        pub heap_used_bytes: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(rename = "scopeText", default, skip_serializing_if = "Option::is_none")]
        pub scope_text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cgroup: Option<Option<String>>,
        #[serde(rename = "cgroupVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cgroup_version: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cpu: Option<sts_model_management_components_4::WithAvailableFromEcsCgroupVersion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub memory: Option<sts_model_management_components_4::WithAvailableFromEcsCgroupVersion2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<sts_model_management_components_4::WithRowsUnansweredDebuggerNote>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ecs: Option<sts_model_management_components_4::WithAvailableEndpointDockerId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub machine: Option<Answer200Machine>,
        #[serde(rename = "answeredBy", default, skip_serializing_if = "Option::is_none")]
        pub answered_by: Option<Answer200AnsweredBy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cluster: Option<sts_model_management_components_4::WithClusteredTextIntervalSeconds2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<Vec<Answer200NodesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
    }
}

/// Run a full V8 garbage collection in this node's front process, one of its
/// worker threads, or all
pub mod collect_garbage {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/node-health/collect-garbage";
    pub const OPERATION_ID: &str = "collectGarbage";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `all`, `front`, or a worker thread's threadId; `all` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<sts_model_base::unions::IntegerOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors15;
}

/// The OpenAPI 3.1 document for this API
pub mod get_open_api {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/openapi.json";
    pub const OPERATION_ID: &str = "getOpenApi";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::OpenApi2;
}

/// The SCEP server: endpoints, Issuing CA, RA certificate, profiles,
/// challenges, host names, certificates, settings
pub mod get_scep {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/scep";
    pub const OPERATION_ID: &str = "getScep";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "certificatesPage", default, skip_serializing_if = "Option::is_none")]
        pub certificates_page: Option<i64>,
        #[serde(rename = "credentialsPage", default, skip_serializing_if = "Option::is_none")]
        pub credentials_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Endpoints {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cgi: Option<String>,
        #[serde(rename = "getCaCaps", default, skip_serializing_if = "Option::is_none")]
        pub get_ca_caps: Option<String>,
        #[serde(rename = "getCaCert", default, skip_serializing_if = "Option::is_none")]
        pub get_ca_cert: Option<String>,
        #[serde(rename = "pkiOperation", default, skip_serializing_if = "Option::is_none")]
        pub pki_operation: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Algorithms {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub digests: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signatures: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ciphers: Option<Vec<String>>,
        #[serde(rename = "keyTransports", default, skip_serializing_if = "Option::is_none")]
        pub key_transports: Option<Vec<String>>,
        #[serde(rename = "refusedDigests", default, skip_serializing_if = "Option::is_none")]
        pub refused_digests: Option<Vec<String>>,
        #[serde(rename = "refusedCiphers", default, skip_serializing_if = "Option::is_none")]
        pub refused_ciphers: Option<Vec<String>>,
        #[serde(rename = "replySignature", default, skip_serializing_if = "Option::is_none")]
        pub reply_signature: Option<String>,
        #[serde(rename = "replyKeyTransport", default, skip_serializing_if = "Option::is_none")]
        pub reply_key_transport: Option<String>,
        #[serde(rename = "replyCipher", default, skip_serializing_if = "Option::is_none")]
        pub reply_cipher: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthorityIntermediate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthorityRoot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authority {
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
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediate: Option<Answer200AuthorityIntermediate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub root: Option<Answer200AuthorityRoot>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProfilesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub needs: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
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
    pub struct Answer200ChallengesRowsItemEntry {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ChallengesRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<Answer200ChallengesRowsItemEntry>,
        #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
        pub entry_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
        pub created_by: Option<String>,
        #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Challenges {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200ChallengesRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ExceptionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ModeRequirement {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub development: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub product: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Mode {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requirement: Option<Answer200ModeRequirement>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scep: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specifications: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Answer200Endpoints>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capabilities: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<String>>,
        #[serde(rename = "messageTypes", default, skip_serializing_if = "Option::is_none")]
        pub message_types: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithms: Option<Answer200Algorithms>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authority: Option<Answer200Authority>,
        #[serde(rename = "hierarchyBuilt", default, skip_serializing_if = "Option::is_none")]
        pub hierarchy_built: Option<bool>,
        #[serde(rename = "authorityNote", default, skip_serializing_if = "Option::is_none")]
        pub authority_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ra: Option<sts_model_management_components_4::WithPresentStatusSubject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<Vec<Answer200ProfilesItem>>,
        #[serde(rename = "refusedProfiles", default, skip_serializing_if = "Option::is_none")]
        pub refused_profiles: Option<Vec<Answer200RefusedProfilesItem>>,
        #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub default_profile: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenges: Option<Answer200Challenges>,
        #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
        pub host_names: Option<sts_model_management_components_4::WithAtOperationOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<sts_model_management_components_4::WithPagingRowsEntry2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exceptions: Option<Vec<Answer200ExceptionsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<Answer200Mode>,
        #[serde(rename = "revokeReasons", default, skip_serializing_if = "Option::is_none")]
        pub revoke_reasons: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Register a DNS name or IP address on an entry
pub mod add_scep_host_name {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scep/add-host-name";
    pub const OPERATION_ID: &str = "addScepHostName";

    /// Whether the entry is a person or an application.
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
        /// Whether the entry is a person or an application.
        pub kind: BodyKind,
        /// The username or the application identifier, in this realm.
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors168;
}

/// Create a single-use SCEP challenge password for one entry and one profile
pub mod create_scep_challenge {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scep/create-challenge";
    pub const OPERATION_ID: &str = "createScepChallenge";

    /// Whether the entry is a person or an application.
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
        /// Whether the entry is a person or an application.
        pub kind: BodyKind,
        /// The username or the application identifier, in this realm.
        pub identifier: String,
        /// One of the nine enrollment profiles.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        /// Seconds it may wait, at most scep.challengeLifetimeS.
        #[serde(rename = "lifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_s: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors165;
}

/// Delete a SCEP challenge password
pub mod delete_scep_challenge {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scep/delete-challenge";
    pub const OPERATION_ID: &str = "deleteScepChallenge";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The challenge id, from GET /admin-api/scep.
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
        pub entry_uri: Option<String>,
    }
}

/// What the SCEP server has done: requests, issuances, refusals by failInfo and
/// by error code
pub mod get_scep_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/scep/monitor";
    pub const OPERATION_ID: &str = "getScepMonitor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
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
        #[serde(rename = "challengesCreated", default, skip_serializing_if = "Option::is_none")]
        pub challenges_created: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub since: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profiles: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub principals: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "errorCodes", default, skip_serializing_if = "Option::is_none")]
        pub error_codes: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub statuses: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "failInfo", default, skip_serializing_if = "Option::is_none")]
        pub fail_info: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "issuedCertificates", default, skip_serializing_if = "Option::is_none")]
        pub issued_certificates: Option<i64>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recent: Option<sts_model_management_components_4::WithOkMessageErrors157>,
    }
}

/// Re-issue the SCEP RA certificate
pub mod reissue_scep_ra {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scep/reissue-ra";
    pub const OPERATION_ID: &str = "reissueScepRa";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors166;
}

/// Remove a registered host name from an entry
pub mod remove_scep_host_name {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scep/remove-host-name";
    pub const OPERATION_ID: &str = "removeScepHostName";

    /// Whether the entry is a person or an application.
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
        /// Whether the entry is a person or an application.
        pub kind: BodyKind,
        /// The username or the application identifier, in this realm.
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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors168;
}

/// Revoke a certificate issued over SCEP
pub mod revoke_scep_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scep/revoke-certificate";
    pub const OPERATION_ID: &str = "revokeScepCertificate";

    /// The RFC 5280 reason.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReason {
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
        #[serde(rename = "privilegeWithdrawn")]
        PrivilegeWithdrawn,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The serial, hexadecimal.
        pub serial: String,
        /// The RFC 5280 reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors167;
}

/// Every scheduled job, its last run and its next, or one run
pub mod get_scheduler {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/scheduler";
    pub const OPERATION_ID: &str = "getScheduler";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOutcome {
        #[serde(rename = "succeeded")]
        Succeeded,
        #[serde(rename = "failed")]
        Failed,
        #[serde(rename = "abandoned")]
        Abandoned,
        #[serde(rename = "running")]
        Running,
        #[serde(rename = "queued")]
        Queued,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "jobsPage", default, skip_serializing_if = "Option::is_none")]
        pub jobs_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub run: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub outcome: Option<QueryOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AnsweredBy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node: Option<String>,
        #[serde(rename = "nodeName", default, skip_serializing_if = "Option::is_none")]
        pub node_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Leader {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clustered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub known: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(rename = "nodeName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node_name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub host: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub since: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub token: Option<Option<f64>>,
        #[serde(rename = "leaseHolder", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub lease_holder: Option<Option<String>>,
        #[serde(rename = "leaseAcquiredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub lease_acquired_at: Option<Option<String>>,
        #[serde(rename = "leaseExpiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub lease_expires_at: Option<Option<String>>,
        #[serde(rename = "lastTickAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_tick_at: Option<Option<String>>,
        #[serde(rename = "lastTickAgoMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_tick_ago_ms: Option<Option<f64>>,
        #[serde(rename = "thisProcess", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub this_process: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub live: Option<Option<bool>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200JobsItemSchedule {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(rename = "everyMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub every_ms: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub setting: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cron: Option<Option<String>>,
        #[serde(rename = "manualOnly", default, skip_serializing_if = "Option::is_none")]
        pub manual_only: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200JobsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub describe: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "readOnly", default, skip_serializing_if = "Option::is_none")]
        pub read_only: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<Answer200JobsItemSchedule>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "offReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub off_reason: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub manual: Option<bool>,
        #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<f64>,
        #[serde(rename = "runsOn", default, skip_serializing_if = "Option::is_none")]
        pub runs_on: Option<String>,
        #[serde(rename = "onFront", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub on_front: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nice: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub processes: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesRunId>,
        #[serde(rename = "lastRun", default, skip_serializing_if = "Option::is_none")]
        pub last_run: Option<sts_model_management_components_2::LastRunValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub running: Option<sts_model_management_components_2::LastRunValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub queued: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesRunId>,
        #[serde(rename = "nextRunAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub next_run_at: Option<Option<String>>,
        #[serde(rename = "nextRunInMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub next_run_in_ms: Option<Option<f64>>,
        #[serde(rename = "nextRunState", default, skip_serializing_if = "Option::is_none")]
        pub next_run_state: Option<String>,
        #[serde(rename = "overdueSince", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub overdue_since: Option<Option<String>>,
        #[serde(rename = "overdueWhy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub overdue_why: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CommandsItemLeaderAtRequest {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub token: Option<Option<f64>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CommandsItemObeyedByV1 {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(rename = "nodeName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node_name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub host: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200CommandsItemObeyedBy {
        V1(Answer200CommandsItemObeyedByV1),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CommandsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub command: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
        pub requested_by: Option<String>,
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub queued_at: Option<Option<String>>,
        #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ended_at: Option<Option<String>>,
        #[serde(rename = "leaderAtRequest", default, skip_serializing_if = "Option::is_none")]
        pub leader_at_request: Option<Answer200CommandsItemLeaderAtRequest>,
        #[serde(rename = "obeyedBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub obeyed_by: Option<Option<Answer200CommandsItemObeyedBy>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filters {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub job: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub outcome: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(rename = "nowMs", default, skip_serializing_if = "Option::is_none")]
        pub now_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clock: Option<String>,
        #[serde(rename = "answeredBy", default, skip_serializing_if = "Option::is_none")]
        pub answered_by: Option<Answer200AnsweredBy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub leader: Option<Answer200Leader>,
        #[serde(rename = "tickS", default, skip_serializing_if = "Option::is_none")]
        pub tick_s: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "unknownDisabledIds", default, skip_serializing_if = "Option::is_none")]
        pub unknown_disabled_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jobs: Option<Vec<Answer200JobsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub runs: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesRunId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub commands: Option<Vec<Answer200CommandsItem>>,
        #[serde(rename = "confinedToRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub confined_to_realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filters: Option<Answer200Filters>,
        #[serde(rename = "runsPaging", default, skip_serializing_if = "Option::is_none")]
        pub runs_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(rename = "jobsPaging", default, skip_serializing_if = "Option::is_none")]
        pub jobs_paging: Option<sts_model_management_components_2::PageHowManyQueryParameter>,
        #[serde(rename = "jobIds", default, skip_serializing_if = "Option::is_none")]
        pub job_ids: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsPageDrawsDescribedSame>,
        /// The run asked for by `?run=`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub run: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<sts_model_management_components_2::LastRunValue>,
    }
}

/// Queue a run of one job now
pub mod run_scheduler_job {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scheduler/run";
    pub const OPERATION_ID: &str = "runSchedulerJob";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The job `id`, as GET /admin-api/scheduler lists it.
        pub job: String,
        /// The realm, for a realm-scoped job; the one the request is in otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        /// Parameters the job reads, where it reads any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub params: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors14;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors14;
}

/// Ask the scheduler's leader to hand over
pub mod step_down_scheduler {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scheduler/step-down";
    pub const OPERATION_ID: &str = "stepDownScheduler";

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

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors14;

    pub type Answer202 = sts_model_management_components_4::WithOkMessageErrors14;
}

/// The SCIM 2.0 provisioning surface, and what it has been asked to do
pub mod get_scim {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/scim";
    pub const OPERATION_ID: &str = "getScim";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Store {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub users: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<String>,
        #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
        pub base_dn: Option<String>,
        #[serde(rename = "userCount", default, skip_serializing_if = "Option::is_none")]
        pub user_count: Option<f64>,
        #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
        pub group_count: Option<f64>,
        #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
        pub entry_count: Option<f64>,
        #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
        pub max_entries: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Identifiers {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub example: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticationScopes {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub read: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub write: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticationSchemesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub canonical: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "refusedByMode", default, skip_serializing_if = "Option::is_none")]
        pub refused_by_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub primary: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scoped: Option<bool>,
        #[serde(rename = "applicationScoped", default, skip_serializing_if = "Option::is_none")]
        pub application_scoped: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub recorded: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenged: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
        #[serde(rename = "specUri", default, skip_serializing_if = "Option::is_none")]
        pub spec_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authentication {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required: Option<bool>,
        #[serde(rename = "discoveryOpen", default, skip_serializing_if = "Option::is_none")]
        pub discovery_open: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Answer200AuthenticationScopes>,
        #[serde(rename = "hobaRegistration", default, skip_serializing_if = "Option::is_none")]
        pub hoba_registration: Option<String>,
        #[serde(rename = "digestAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub digest_algorithms: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schemes: Option<Vec<Answer200AuthenticationSchemesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Vec<String>>,
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
    #[serde(deny_unknown_fields)]
    pub struct Answer200Mapping {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesPage3>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesPage3>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CountersOperationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CountersResourceTypesItem {
        #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub resource_type: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counters {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<f64>,
        #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operations: Option<Vec<Answer200CountersOperationsItem>>,
        #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
        pub resource_types: Option<Vec<Answer200CountersResourceTypesItem>>,
        /// A count per name.
        #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
        pub by_status: Option<serde_json::Map<String, serde_json::Value>>,
        /// A count per name.
        #[serde(rename = "byScimType", default, skip_serializing_if = "Option::is_none")]
        pub by_scim_type: Option<serde_json::Map<String, serde_json::Value>>,
        /// A count per name.
        #[serde(rename = "byAuthScheme", default, skip_serializing_if = "Option::is_none")]
        pub by_auth_scheme: Option<serde_json::Map<String, serde_json::Value>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ScimClients {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<sts_model_management_components_4::WithAuthMethodsOauthClientAuthTlsSources>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub choices: Option<sts_model_management_components_4::WithAuthMethodsOauthClientAuthTlsSources2>,
        #[serde(rename = "httpAllowed", default, skip_serializing_if = "Option::is_none")]
        pub http_allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<sts_model_management_components_1::ClientValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<String>,
        #[serde(rename = "cellId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cell_id: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub installed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub base_url: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specifications: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub store: Option<Answer200Store>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifiers: Option<Answer200Identifiers>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication: Option<Answer200Authentication>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Vec<Answer200EndpointsItem>>,
        #[serde(rename = "doesNotDo", default, skip_serializing_if = "Option::is_none")]
        pub does_not_do: Option<Vec<String>>,
        #[serde(rename = "reachableNegatives", default, skip_serializing_if = "Option::is_none")]
        pub reachable_negatives: Option<Vec<Answer200ReachableNegativesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mapping: Option<Answer200Mapping>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counters: Option<Answer200Counters>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue4>,
        #[serde(rename = "scimClients", default, skip_serializing_if = "Option::is_none")]
        pub scim_clients: Option<Answer200ScimClients>,
    }
}

/// This realm's outbound SCIM clients (#552)
pub mod get_scim_clients {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/scim/clients";
    pub const OPERATION_ID: &str = "getScimClients";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<sts_model_management_components_4::WithAuthMethodsOauthClientAuthTlsSources>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub choices: Option<sts_model_management_components_4::WithAuthMethodsOauthClientAuthTlsSources2>,
        #[serde(rename = "httpAllowed", default, skip_serializing_if = "Option::is_none")]
        pub http_allowed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client: Option<sts_model_management_components_1::ClientValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub missing: Option<String>,
        #[serde(rename = "cellId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub cell_id: Option<Option<String>>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Add an outbound SCIM client
pub mod add_scim_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/add-client";
    pub const OPERATION_ID: &str = "addScimClient";

    /// Whether changes are pushed. A new client is off until this says true.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyEnabled {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
    }

    /// basic, oauth2 (client_credentials), or none (only with a TLS client
    /// certificate).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAuthMethod {
        #[serde(rename = "basic")]
        Basic,
        #[serde(rename = "oauth2")]
        Oauth2,
        #[serde(rename = "none")]
        None,
    }

    /// oauth2: how the client authenticates at the token endpoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOauthClientAuth {
        #[serde(rename = "client_secret_basic")]
        ClientSecretBasic,
        #[serde(rename = "client_secret_post")]
        ClientSecretPost,
    }

    /// The TLS client certificate: none, issued (issue-certificate) or uploaded.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTlsSource {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "uploaded")]
        Uploaded,
    }

    /// Who is pushed: all, groups, or filter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyScopeMode {
        #[serde(rename = "all")]
        All,
        #[serde(rename = "groups")]
        Groups,
        #[serde(rename = "filter")]
        Filter,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyScopeGroups {
        V1(Vec<String>),
        String(String),
    }

    /// Which groups are pushed: none, selected, member-groups or all.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyGroupMode {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "selected")]
        Selected,
        #[serde(rename = "member-groups")]
        MemberGroups,
        #[serde(rename = "all")]
        All,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyGroups {
        V1(Vec<String>),
        String(String),
    }

    /// What leaving the scope does there: deactivate (active false) or delete.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDeprovision {
        #[serde(rename = "deactivate")]
        Deactivate,
        #[serde(rename = "delete")]
        Delete,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyCells {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client's application identifier (add only): the entry it is filed
        /// under in ou=applications.
        pub identifier: String,
        /// What to call it on a page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Whether changes are pushed. A new client is off until this says true.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<BodyEnabled>,
        /// The service provider's SCIM base URI (RFC 7644 section 1.3): https, no
        /// user name, no query.
        #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
        pub base_url: Option<String>,
        /// basic, oauth2 (client_credentials), or none (only with a TLS client
        /// certificate).
        #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
        pub auth_method: Option<BodyAuthMethod>,
        /// basic: the user name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// basic: the password, write-only. On a change, empty keeps the one set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// oauth2: the token endpoint.
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        /// oauth2: the client_id.
        #[serde(rename = "oauthClientId", default, skip_serializing_if = "Option::is_none")]
        pub oauth_client_id: Option<String>,
        /// oauth2: the client secret, write-only.
        #[serde(rename = "oauthClientSecret", default, skip_serializing_if = "Option::is_none")]
        pub oauth_client_secret: Option<String>,
        /// oauth2: how the client authenticates at the token endpoint.
        #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
        pub oauth_client_auth: Option<BodyOauthClientAuth>,
        /// oauth2: the scope asked for, if any.
        #[serde(rename = "oauthScope", default, skip_serializing_if = "Option::is_none")]
        pub oauth_scope: Option<String>,
        /// oauth2: an RFC 8707 resource, if any.
        #[serde(rename = "oauthResource", default, skip_serializing_if = "Option::is_none")]
        pub oauth_resource: Option<String>,
        /// The TLS client certificate: none, issued (issue-certificate) or
        /// uploaded.
        #[serde(rename = "tlsSource", default, skip_serializing_if = "Option::is_none")]
        pub tls_source: Option<BodyTlsSource>,
        /// uploaded: the PEM certificate and its chain.
        #[serde(rename = "tlsCertificate", default, skip_serializing_if = "Option::is_none")]
        pub tls_certificate: Option<String>,
        /// uploaded: the PEM private key, write-only.
        #[serde(rename = "tlsPrivateKey", default, skip_serializing_if = "Option::is_none")]
        pub tls_private_key: Option<String>,
        /// PEM certificates trusted for the service provider beside the public
        /// roots.
        #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
        pub ca_certificates: Option<String>,
        /// Who is pushed: all, groups, or filter.
        #[serde(rename = "scopeMode", default, skip_serializing_if = "Option::is_none")]
        pub scope_mode: Option<BodyScopeMode>,
        /// groups: the groups whose members are pushed, by cn or DN.
        #[serde(rename = "scopeGroups", default, skip_serializing_if = "Option::is_none")]
        pub scope_groups: Option<BodyScopeGroups>,
        /// filter: an RFC 4515 LDAP filter.
        #[serde(rename = "scopeFilter", default, skip_serializing_if = "Option::is_none")]
        pub scope_filter: Option<String>,
        /// Which groups are pushed: none, selected, member-groups or all.
        #[serde(rename = "groupMode", default, skip_serializing_if = "Option::is_none")]
        pub group_mode: Option<BodyGroupMode>,
        /// selected: the groups pushed, by cn or DN.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<BodyGroups>,
        /// What leaving the scope does there: deactivate (active false) or delete.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deprovision: Option<BodyDeprovision>,
        /// Minutes between scheduled reconciliations; 0 is on demand only.
        #[serde(rename = "reconcileMinutes", default, skip_serializing_if = "Option::is_none")]
        pub reconcile_minutes: Option<String>,
        /// The most requests a second the service provider is sent; every request
        /// waits for its turn rather than failing. Empty or 0 is no limit. In a
        /// service deployed as cells each pushing cell may send this divided by the
        /// pushing cells, rounded up (#553).
        #[serde(rename = "maxRequestsPerSecond", default, skip_serializing_if = "Option::is_none")]
        pub max_requests_per_second: Option<String>,
        /// A service deployed as cells (#553): the jurisdiction the service
        /// provider is in, as the cell map spells one (us, eu, ca). Each person's
        /// home cell asks the issuance policy (release-attributes, purpose
        /// scim-provision) before pushing them there; a refusal leaves them out of
        /// scope. Empty is unknown, which the strict default never releases to.
        /// Ignored in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jurisdiction: Option<String>,
        /// A service deployed as cells (#553): the cells that push to the service
        /// provider, by id; empty is every cell. Ignored in a service that is one
        /// cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cells: Option<BodyCells>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Lift the client's pause and send its queue
pub mod deliver_scim_client_now {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/deliver-now";
    pub const OPERATION_ID: &str = "deliverScimClientNow";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
        /// A service deployed as cells (#553): the cell the act is sent to. Without
        /// it the act goes to every cell that pushes to the client, and the answer
        /// lists each cell's result. Refused in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Issue the client a TLS client certificate
pub mod issue_scim_client_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/issue-certificate";
    pub const OPERATION_ID: &str = "issueScimClientCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Purge a client's dead letters
pub mod purge_scim_dead_letters {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/purge-dead";
    pub const OPERATION_ID: &str = "purgeScimDeadLetters";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
        /// A service deployed as cells (#553): the cell the act is sent to. Without
        /// it the act goes to every cell that pushes to the client, and the answer
        /// lists each cell's result. Refused in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Reconcile the client now
pub mod reconcile_scim_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/reconcile";
    pub const OPERATION_ID: &str = "reconcileScimClient";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
        /// A service deployed as cells (#553): the cell the act is sent to. Without
        /// it the act goes to every cell that pushes to the client, and the answer
        /// lists each cell's result. Refused in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Remove an outbound SCIM client
pub mod remove_scim_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/remove-client";
    pub const OPERATION_ID: &str = "removeScimClient";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Retry every dead letter of a client
pub mod retry_scim_dead_letters {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/retry-dead";
    pub const OPERATION_ID: &str = "retryScimDeadLetters";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
        /// A service deployed as cells (#553): the cell the act is sent to. Without
        /// it the act goes to every cell that pushes to the client, and the answer
        /// lists each cell's result. Refused in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Retry one dead letter
pub mod retry_scim_delivery {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/retry-delivery";
    pub const OPERATION_ID: &str = "retryScimDelivery";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The delivery row's id.
        pub id: String,
        /// A service deployed as cells (#553): the cell the act is sent to. Without
        /// it the act goes to every cell that pushes to the client, and the answer
        /// lists each cell's result. Refused in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Read the service provider's configuration
pub mod test_scim_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/test-connection";
    pub const OPERATION_ID: &str = "testScimClient";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// Change an outbound SCIM client
pub mod update_scim_client {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/scim/clients/update-client";
    pub const OPERATION_ID: &str = "updateScimClient";

    /// Whether changes are pushed. A new client is off until this says true.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyEnabled {
        #[serde(rename = "true")]
        True,
        #[serde(rename = "false")]
        False,
    }

    /// basic, oauth2 (client_credentials), or none (only with a TLS client
    /// certificate).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAuthMethod {
        #[serde(rename = "basic")]
        Basic,
        #[serde(rename = "oauth2")]
        Oauth2,
        #[serde(rename = "none")]
        None,
    }

    /// oauth2: how the client authenticates at the token endpoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyOauthClientAuth {
        #[serde(rename = "client_secret_basic")]
        ClientSecretBasic,
        #[serde(rename = "client_secret_post")]
        ClientSecretPost,
    }

    /// The TLS client certificate: none, issued (issue-certificate) or uploaded.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTlsSource {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "issued")]
        Issued,
        #[serde(rename = "uploaded")]
        Uploaded,
    }

    /// Who is pushed: all, groups, or filter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyScopeMode {
        #[serde(rename = "all")]
        All,
        #[serde(rename = "groups")]
        Groups,
        #[serde(rename = "filter")]
        Filter,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyScopeGroups {
        V1(Vec<String>),
        String(String),
    }

    /// Which groups are pushed: none, selected, member-groups or all.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyGroupMode {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "selected")]
        Selected,
        #[serde(rename = "member-groups")]
        MemberGroups,
        #[serde(rename = "all")]
        All,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyGroups {
        V1(Vec<String>),
        String(String),
    }

    /// What leaving the scope does there: deactivate (active false) or delete.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDeprovision {
        #[serde(rename = "deactivate")]
        Deactivate,
        #[serde(rename = "delete")]
        Delete,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyCells {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The client: its identifier or its entry's DN.
        pub id: String,
        /// What to call it on a page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Whether changes are pushed. A new client is off until this says true.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<BodyEnabled>,
        /// The service provider's SCIM base URI (RFC 7644 section 1.3): https, no
        /// user name, no query.
        #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
        pub base_url: Option<String>,
        /// basic, oauth2 (client_credentials), or none (only with a TLS client
        /// certificate).
        #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
        pub auth_method: Option<BodyAuthMethod>,
        /// basic: the user name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// basic: the password, write-only. On a change, empty keeps the one set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
        /// oauth2: the token endpoint.
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        /// oauth2: the client_id.
        #[serde(rename = "oauthClientId", default, skip_serializing_if = "Option::is_none")]
        pub oauth_client_id: Option<String>,
        /// oauth2: the client secret, write-only.
        #[serde(rename = "oauthClientSecret", default, skip_serializing_if = "Option::is_none")]
        pub oauth_client_secret: Option<String>,
        /// oauth2: how the client authenticates at the token endpoint.
        #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
        pub oauth_client_auth: Option<BodyOauthClientAuth>,
        /// oauth2: the scope asked for, if any.
        #[serde(rename = "oauthScope", default, skip_serializing_if = "Option::is_none")]
        pub oauth_scope: Option<String>,
        /// oauth2: an RFC 8707 resource, if any.
        #[serde(rename = "oauthResource", default, skip_serializing_if = "Option::is_none")]
        pub oauth_resource: Option<String>,
        /// The TLS client certificate: none, issued (issue-certificate) or
        /// uploaded.
        #[serde(rename = "tlsSource", default, skip_serializing_if = "Option::is_none")]
        pub tls_source: Option<BodyTlsSource>,
        /// uploaded: the PEM certificate and its chain.
        #[serde(rename = "tlsCertificate", default, skip_serializing_if = "Option::is_none")]
        pub tls_certificate: Option<String>,
        /// uploaded: the PEM private key, write-only.
        #[serde(rename = "tlsPrivateKey", default, skip_serializing_if = "Option::is_none")]
        pub tls_private_key: Option<String>,
        /// PEM certificates trusted for the service provider beside the public
        /// roots.
        #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
        pub ca_certificates: Option<String>,
        /// Who is pushed: all, groups, or filter.
        #[serde(rename = "scopeMode", default, skip_serializing_if = "Option::is_none")]
        pub scope_mode: Option<BodyScopeMode>,
        /// groups: the groups whose members are pushed, by cn or DN.
        #[serde(rename = "scopeGroups", default, skip_serializing_if = "Option::is_none")]
        pub scope_groups: Option<BodyScopeGroups>,
        /// filter: an RFC 4515 LDAP filter.
        #[serde(rename = "scopeFilter", default, skip_serializing_if = "Option::is_none")]
        pub scope_filter: Option<String>,
        /// Which groups are pushed: none, selected, member-groups or all.
        #[serde(rename = "groupMode", default, skip_serializing_if = "Option::is_none")]
        pub group_mode: Option<BodyGroupMode>,
        /// selected: the groups pushed, by cn or DN.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<BodyGroups>,
        /// What leaving the scope does there: deactivate (active false) or delete.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deprovision: Option<BodyDeprovision>,
        /// Minutes between scheduled reconciliations; 0 is on demand only.
        #[serde(rename = "reconcileMinutes", default, skip_serializing_if = "Option::is_none")]
        pub reconcile_minutes: Option<String>,
        /// The most requests a second the service provider is sent; every request
        /// waits for its turn rather than failing. Empty or 0 is no limit. In a
        /// service deployed as cells each pushing cell may send this divided by the
        /// pushing cells, rounded up (#553).
        #[serde(rename = "maxRequestsPerSecond", default, skip_serializing_if = "Option::is_none")]
        pub max_requests_per_second: Option<String>,
        /// A service deployed as cells (#553): the jurisdiction the service
        /// provider is in, as the cell map spells one (us, eu, ca). Each person's
        /// home cell asks the issuance policy (release-attributes, purpose
        /// scim-provision) before pushing them there; a refusal leaves them out of
        /// scope. Empty is unknown, which the strict default never releases to.
        /// Ignored in a service that is one cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jurisdiction: Option<String>,
        /// A service deployed as cells (#553): the cells that push to the service
        /// provider, by id; empty is every cell. Ignored in a service that is one
        /// cell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cells: Option<BodyCells>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors191;
}

/// How many SCIM calls there have been, from whom, of what kind, and how many
/// failed
pub mod get_scim_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/scim/monitor";
    pub const OPERATION_ID: &str = "getScimMonitor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::ScimMonitor;
}

/// Where the key-encryption key and the database password come from, and what
/// the store holding them is doing
pub mod get_secrets {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/secrets";
    pub const OPERATION_ID: &str = "getSecrets";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200StoresItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secrets: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub probes: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SecretsItemSettings {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub provider: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub location: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub field: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SecretsItemLastRead {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(rename = "tookMs", default, skip_serializing_if = "Option::is_none")]
        pub took_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SecretsItem {
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
        pub where_: Option<sts_model_management_components_4::WithFromSharedRegion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shared: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Answer200SecretsItemSettings>,
        #[serde(rename = "lastRead", default, skip_serializing_if = "Option::is_none")]
        pub last_read: Option<Answer200SecretsItemLastRead>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub store: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub probes: Option<sts_model_management_components_4::WithAdditionalPropertiesPropertiesPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200ProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stores: Option<Vec<Answer200StoresItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub secrets: Option<Vec<Answer200SecretsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<String>,
        #[serde(rename = "productMode", default, skip_serializing_if = "Option::is_none")]
        pub product_mode: Option<bool>,
        #[serde(rename = "persistingKeys", default, skip_serializing_if = "Option::is_none")]
        pub persisting_keys: Option<bool>,
        #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
        pub key_source: Option<String>,
        #[serde(rename = "kekHeld", default, skip_serializing_if = "Option::is_none")]
        pub kek_held: Option<bool>,
        /// What each secret is for, by its id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<serde_json::Map<String, serde_json::Value>>,
    }
}

/// The trust domain: its authorities, its bundle, its listeners
pub mod get_spiffe {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/spiffe";
    pub const OPERATION_ID: &str = "getSpiffe";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Bundle {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sequence: Option<f64>,
        #[serde(rename = "refreshHint", default, skip_serializing_if = "Option::is_none")]
        pub refresh_hint: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthoritiesX509Item {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
        pub key_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthoritiesJwtItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
        pub key_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwk: Option<sts_model_management_components_2::JwkValue>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthoritiesTrustAnchorsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthoritiesRoot {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<String>>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub not_after: Option<Option<String>>,
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub certificate_pem: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authorities {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub x509: Option<Vec<Answer200AuthoritiesX509Item>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwt: Option<Vec<Answer200AuthoritiesJwtItem>>,
        #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchors: Option<Vec<Answer200AuthoritiesTrustAnchorsItem>>,
        #[serde(rename = "chainSubjects", default, skip_serializing_if = "Option::is_none")]
        pub chain_subjects: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub root: Option<Answer200AuthoritiesRoot>,
        #[serde(rename = "maxRetained", default, skip_serializing_if = "Option::is_none")]
        pub max_retained: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Listeners {
        #[serde(rename = "workloadApi", default, skip_serializing_if = "Option::is_none")]
        pub workload_api: Option<sts_model_management_components_4::WithTrustDomainTrustDomainIdX509Keys>,
        #[serde(rename = "serverApi", default, skip_serializing_if = "Option::is_none")]
        pub server_api: Option<sts_model_management_components_4::WithTrustDomainTrustDomainIdX509Keys>,
        #[serde(rename = "brokerApi", default, skip_serializing_if = "Option::is_none")]
        pub broker_api: Option<sts_model_management_components_4::WithTrustDomainTrustDomainIdX509Keys>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WorkloadAttestationTcp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub port: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub served: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub declared: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listening: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attested: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WorkloadAttestationAttestorsItem {
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verifies: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WorkloadAttestationConnectionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uid: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gid: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub visible: Option<bool>,
        #[serde(rename = "pidfdSource", default, skip_serializing_if = "Option::is_none")]
        pub pidfd_source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub error: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub note: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200WorkloadAttestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tcp: Option<Answer200WorkloadAttestationTcp>,
        #[serde(rename = "nativeModule", default, skip_serializing_if = "Option::is_none")]
        pub native_module: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub problem: Option<Option<String>>,
        #[serde(rename = "unattestedSocketServed", default, skip_serializing_if = "Option::is_none")]
        pub unattested_socket_served: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attestors: Option<Vec<Answer200WorkloadAttestationAttestorsItem>>,
        #[serde(rename = "unknownConfigured", default, skip_serializing_if = "Option::is_none")]
        pub unknown_configured: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connections: Option<Vec<Answer200WorkloadAttestationConnectionsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agents: Option<i64>,
        #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
        pub max_entries: Option<f64>,
        #[serde(rename = "maxAgents", default, skip_serializing_if = "Option::is_none")]
        pub max_agents: Option<f64>,
        #[serde(rename = "maxFederatedBundles", default, skip_serializing_if = "Option::is_none")]
        pub max_federated_bundles: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeyTypesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(rename = "jwtAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub jwt_alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticationEntitiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthenticationPolicyItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allow: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Authentication {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bootstrapping: Option<String>,
        #[serde(rename = "identityNote", default, skip_serializing_if = "Option::is_none")]
        pub identity_note: Option<String>,
        #[serde(rename = "credentialStatusNote", default, skip_serializing_if = "Option::is_none")]
        pub credential_status_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enforced: Option<bool>,
        #[serde(rename = "trustLocalSocket", default, skip_serializing_if = "Option::is_none")]
        pub trust_local_socket: Option<bool>,
        #[serde(rename = "adminIds", default, skip_serializing_if = "Option::is_none")]
        pub admin_ids: Option<Vec<String>>,
        #[serde(rename = "attestWorkloads", default, skip_serializing_if = "Option::is_none")]
        pub attest_workloads: Option<bool>,
        #[serde(rename = "acceptAssertedSelectors", default, skip_serializing_if = "Option::is_none")]
        pub accept_asserted_selectors: Option<bool>,
        #[serde(rename = "assertedSelectorHeader", default, skip_serializing_if = "Option::is_none")]
        pub asserted_selector_header: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entities: Option<Vec<Answer200AuthenticationEntitiesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<Vec<Answer200AuthenticationPolicyItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SettingsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub value: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthorityStateX509AuthoritiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
        pub key_type: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthorityStateJwtAuthoritiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub not_after: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alg: Option<Option<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AuthorityState {
        #[serde(rename = "x509Authorities", default, skip_serializing_if = "Option::is_none")]
        pub x509_authorities: Option<Vec<Answer200AuthorityStateX509AuthoritiesItem>>,
        #[serde(rename = "jwtAuthorities", default, skip_serializing_if = "Option::is_none")]
        pub jwt_authorities: Option<Vec<Answer200AuthorityStateJwtAuthoritiesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub federated: Option<sts_model_management_components_4::WithIdDnSpiffeId>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ready: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(rename = "trustDomain", default, skip_serializing_if = "Option::is_none")]
        pub trust_domain: Option<String>,
        #[serde(rename = "trustDomainId", default, skip_serializing_if = "Option::is_none")]
        pub trust_domain_id: Option<String>,
        #[serde(rename = "serverId", default, skip_serializing_if = "Option::is_none")]
        pub server_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bundle: Option<Answer200Bundle>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorities: Option<Answer200Authorities>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listeners: Option<Answer200Listeners>,
        #[serde(rename = "workloadAttestation", default, skip_serializing_if = "Option::is_none")]
        pub workload_attestation: Option<Answer200WorkloadAttestation>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub federated: Option<sts_model_management_components_4::WithIdDnSpiffeId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(rename = "keyTypes", default, skip_serializing_if = "Option::is_none")]
        pub key_types: Option<Vec<Answer200KeyTypesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication: Option<Answer200Authentication>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<Vec<Answer200SettingsItem>>,
        #[serde(rename = "authorityState", default, skip_serializing_if = "Option::is_none")]
        pub authority_state: Option<Answer200AuthorityState>,
        #[serde(rename = "serverApiAuthenticated", default, skip_serializing_if = "Option::is_none")]
        pub server_api_authenticated: Option<bool>,
        #[serde(rename = "settingsForms", default, skip_serializing_if = "Option::is_none")]
        pub settings_forms: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// The agents that have attested here, filtered and paged
pub mod get_spiffe_agents {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/spiffe/agents";
    pub const OPERATION_ID: &str = "getSpiffeAgents";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent: Option<String>,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub container: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "serverApiAuthenticated", default, skip_serializing_if = "Option::is_none")]
        pub server_api_authenticated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agents: Option<Vec<sts_model_management_components_4::WithIdDnAttestationType>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent: Option<sts_model_management_components_4::WithIdDnAttestationType>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Refuse this agent at AttestAgent
pub mod ban_spiffe_agent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/agents/ban";
    pub const OPERATION_ID: &str = "banSpiffeAgent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The agent's SPIFFE ID.
        pub agent: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors155;
}

/// Forget an agent
pub mod delete_spiffe_agent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/agents/delete";
    pub const OPERATION_ID: &str = "deleteSpiffeAgent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The agent's SPIFFE ID.
        pub agent: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors155;
}

/// Mint a join token for a workload agent
pub mod create_spiffe_join_token {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/agents/join-token";
    pub const OPERATION_ID: &str = "createSpiffeJoinToken";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Lifetime in seconds. Omit it to use spiffe.joinTokenTtl.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ttl: Option<f64>,
        /// Optional alias SPIFFE ID, registered as an entry parented on the agent
        /// this token attests.
        #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
        pub agent_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors156;
}

/// Let this agent attest again
pub mod unban_spiffe_agent {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/agents/unban";
    pub const OPERATION_ID: &str = "unbanSpiffeAgent";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The agent's SPIFFE ID.
        pub agent: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors155;
}

/// Who may call the SPIFFE Broker API, filtered and paged
pub mod get_spiffe_brokers {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/spiffe/brokers";
    pub const OPERATION_ID: &str = "getSpiffeBrokers";

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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200BrokersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "referenceTypes", default, skip_serializing_if = "Option::is_none")]
        pub reference_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub problem: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "trustDomain", default, skip_serializing_if = "Option::is_none")]
        pub trust_domain: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub port: Option<Option<String>>,
        #[serde(rename = "referenceTypes", default, skip_serializing_if = "Option::is_none")]
        pub reference_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub listeners: Option<sts_model_management_components_4::WithTrustDomainTrustDomainIdX509Keys>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub brokers: Option<Vec<Answer200BrokersItem>>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Take a broker off the list
pub mod remove_spiffe_broker {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/brokers/remove";
    pub const OPERATION_ID: &str = "removeSpiffeBroker";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The broker's SPIFFE ID.
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }
}

/// Authorize a broker, or replace what it may reference
pub mod set_spiffe_broker {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/brokers/set";
    pub const OPERATION_ID: &str = "setSpiffeBroker";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReferenceTypesItem {
        #[serde(rename = "pid")]
        Pid,
        #[serde(rename = "k8s")]
        K8s,
        #[serde(rename = "*")]
        Empty,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The broker's SPIFFE ID.
        pub id: String,
        /// What it may reference: one or more of pid, k8s and *.
        #[serde(rename = "referenceTypes")]
        pub reference_types: Vec<BodyReferenceTypesItem>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors154;
}

/// The registration entries, filtered and paged
pub mod get_spiffe_entries {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/spiffe/entries";
    pub const OPERATION_ID: &str = "getSpiffeEntries";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryOrigin {
        #[serde(rename = "seed")]
        Seed,
        #[serde(rename = "console")]
        Console,
        #[serde(rename = "api")]
        Api,
        #[serde(rename = "grpc")]
        Grpc,
        #[serde(rename = "auto")]
        Auto,
        #[serde(rename = "ldap")]
        Ldap,
        #[serde(rename = "unstated")]
        Unstated,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origin: Option<QueryOrigin>,
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
        pub origin: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Defaults {
        #[serde(rename = "x509SvidTtl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub x509_svid_ttl: Option<Option<String>>,
        #[serde(rename = "jwtSvidTtl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub jwt_svid_ttl: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origins: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub container: Option<String>,
        #[serde(rename = "serverApiAuthenticated", default, skip_serializing_if = "Option::is_none")]
        pub server_api_authenticated: Option<bool>,
        #[serde(rename = "trustDomain", default, skip_serializing_if = "Option::is_none")]
        pub trust_domain: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<Vec<sts_model_management_components_3::SpiffeRegistrationView>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry: Option<sts_model_management_components_3::SpiffeRegistrationView>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub editable: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub defaults: Option<Answer200Defaults>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Register an identity
pub mod create_spiffe_entry {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/entries/create";
    pub const OPERATION_ID: &str = "createSpiffeEntry";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The identity this entry grants.
        #[serde(rename = "spiffeId")]
        pub spiffe_id: String,
        /// The agent or server it hangs beneath. Defaults to this server's own
        /// SPIFFE ID, which is what SPIRE uses for an entry describing a workload
        /// rather than a node.
        #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
        pub parent_id: Option<String>,
        /// Comma-separated `type:value` pairs, split on the FIRST colon only — so
        /// `docker:label:app:web` is type `docker` and value `label:app:web`. An
        /// entry with NO selectors matches every workload, which is how a catch-all
        /// is written and is also the shape of one somebody forgot to finish.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selectors: Option<String>,
        /// Comma-separated DNS subjectAltNames, added beside the SPIFFE ID. What
        /// makes an SVID usable by TLS software that checks a hostname and cannot
        /// read a SPIFFE ID.
        #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
        pub dns_names: Option<String>,
        /// Comma-separated trust domain names whose bundles are handed to a holder
        /// of this identity. A name with no bundle here contributes nothing rather
        /// than failing.
        #[serde(rename = "federatesWith", default, skip_serializing_if = "Option::is_none")]
        pub federates_with: Option<String>,
        /// Seconds. 0 means spiffe.svidTtl.
        #[serde(rename = "x509SvidTtl", default, skip_serializing_if = "Option::is_none")]
        pub x509_svid_ttl: Option<i64>,
        /// Seconds. 0 means spiffe.jwtSvidTtl.
        #[serde(rename = "jwtSvidTtl", default, skip_serializing_if = "Option::is_none")]
        pub jwt_svid_ttl: Option<i64>,
        /// Operator guidance when a workload gets more than one SVID — `internal`,
        /// `external`. Passed through verbatim; nothing here reads it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hint: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors153;
}

/// Remove an entry
pub mod delete_spiffe_entry {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/entries/delete";
    pub const OPERATION_ID: &str = "deleteSpiffeEntry";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The entry id.
        pub entry: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors153;
}

/// Change one field of an entry
pub mod update_spiffe_entry {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/entries/update";
    pub const OPERATION_ID: &str = "updateSpiffeEntry";

    /// Which field. Anything else is refused naming these.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyField {
        #[serde(rename = "spiffeId")]
        SpiffeId,
        #[serde(rename = "parentId")]
        ParentId,
        #[serde(rename = "selectors")]
        Selectors,
        #[serde(rename = "dnsNames")]
        DnsNames,
        #[serde(rename = "federatesWith")]
        FederatesWith,
        #[serde(rename = "x509SvidTtl")]
        X509SvidTtl,
        #[serde(rename = "jwtSvidTtl")]
        JwtSvidTtl,
        #[serde(rename = "hint")]
        Hint,
        #[serde(rename = "expiresAt")]
        ExpiresAt,
        #[serde(rename = "admin")]
        Admin,
        #[serde(rename = "downstream")]
        Downstream,
        #[serde(rename = "storeSvid")]
        StoreSvid,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The entry id.
        pub entry: String,
        /// Which field. Anything else is refused naming these.
        pub field: BodyField,
        /// A list field takes comma-separated values and an empty value CLEARS it;
        /// a boolean takes true or false; a TTL takes seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors153;
}

/// Forget a foreign trust domain's bundle
pub mod remove_spiffe_federated_bundle {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/federation-remove";
    pub const OPERATION_ID: &str = "removeSpiffeFederatedBundle";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The trust domain name.
        #[serde(rename = "trustDomain")]
        pub trust_domain: String,
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

/// Add or replace a foreign trust domain's bundle
pub mod set_spiffe_federated_bundle {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/federation-set";
    pub const OPERATION_ID: &str = "setSpiffeFederatedBundle";

    /// Which profile the partner expects. Recorded.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyBundleEndpointProfile {
        #[serde(rename = "https_web")]
        HttpsWeb,
        #[serde(rename = "https_spiffe")]
        HttpsSpiffe,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The trust domain NAME — `other.example`, not `spiffe://other.example`.
        /// This service's own is refused: a trust domain does not federate with
        /// itself, and accepting it would give it two bundles that could disagree.
        #[serde(rename = "trustDomain")]
        pub trust_domain: String,
        /// The bundle, as a JWK Set with `spiffe_sequence` and
        /// `spiffe_refresh_hint`. A JSON string is accepted too, which is what the
        /// console's textarea sends.
        pub document: serde_json::Map<String, serde_json::Value>,
        /// Recorded and never fetched. It is reported back so an operator can see
        /// what the relationship says.
        #[serde(rename = "bundleEndpointUrl", default, skip_serializing_if = "Option::is_none")]
        pub bundle_endpoint_url: Option<String>,
        /// Which profile the partner expects. Recorded.
        #[serde(rename = "bundleEndpointProfile", default, skip_serializing_if = "Option::is_none")]
        pub bundle_endpoint_profile: Option<BodyBundleEndpointProfile>,
        /// For `https_spiffe`, the SPIFFE ID the partner's endpoint presents.
        /// Recorded.
        #[serde(rename = "endpointSpiffeId", default, skip_serializing_if = "Option::is_none")]
        pub endpoint_spiffe_id: Option<String>,
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

/// Rotate the X.509 authority, the JWT authority, or both
pub mod rotate_spiffe_authority {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/spiffe/rotate";
    pub const OPERATION_ID: &str = "rotateSpiffeAuthority";

    /// Which authority. Defaults to x509.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyWhich {
        #[serde(rename = "x509")]
        X509,
        #[serde(rename = "jwt")]
        Jwt,
        #[serde(rename = "both")]
        Both,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which authority. Defaults to x509.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub which: Option<BodyWhich>,
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

/// What this service is and how much it has done
pub mod get_status {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/status";
    pub const OPERATION_ID: &str = "getStatus";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_3::Status;
}

/// Every protocol, endpoint and specification this serves
pub mod get_sts_metadata {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/sts-metadata";
    pub const OPERATION_ID: &str = "getStsMetadata";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Build {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub release: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub commit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stamped: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200EndpointsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub methods: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specs: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub documented: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub linkable: Option<bool>,
        #[serde(rename = "notLinkableBecause", default, skip_serializing_if = "Option::is_none")]
        pub not_linkable_because: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub effect: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SpecificationsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub coverage: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProtocolsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sockets: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specs: Option<Vec<String>>,
        #[serde(rename = "notAProtocol", default, skip_serializing_if = "Option::is_none")]
        pub not_a_protocol: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specs: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub effect: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub coverage: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub methods: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub documented: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NamedServersItemUrls {
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
    pub struct Answer200NamedServersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub description: Option<Option<String>>,
        /// The metadata members this server overrides.
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
        pub seen: Option<i64>,
        #[serde(rename = "seenAt", default, skip_serializing_if = "Option::is_none")]
        pub seen_at: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
        pub created_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub urls: Option<Answer200NamedServersItemUrls>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub service: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub build: Option<Answer200Build>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(rename = "wsTrustIssuer", default, skip_serializing_if = "Option::is_none")]
        pub ws_trust_issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub port: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
        #[serde(rename = "testDouble", default, skip_serializing_if = "Option::is_none")]
        pub test_double: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Vec<Answer200EndpointsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub specifications: Option<Vec<Answer200SpecificationsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocols: Option<Vec<Answer200ProtocolsItem>>,
        #[serde(rename = "undocumentedPaths", default, skip_serializing_if = "Option::is_none")]
        pub undocumented_paths: Option<Vec<String>>,
        #[serde(rename = "stalePaths", default, skip_serializing_if = "Option::is_none")]
        pub stale_paths: Option<Vec<String>>,
        #[serde(rename = "unknownSpecIds", default, skip_serializing_if = "Option::is_none")]
        pub unknown_spec_ids: Option<Vec<String>>,
        #[serde(rename = "unknownProtocolGroups", default, skip_serializing_if = "Option::is_none")]
        pub unknown_protocol_groups: Option<Vec<String>>,
        #[serde(rename = "unknownProtocolSpecIds", default, skip_serializing_if = "Option::is_none")]
        pub unknown_protocol_spec_ids: Option<Vec<String>>,
        #[serde(rename = "unclaimedGroups", default, skip_serializing_if = "Option::is_none")]
        pub unclaimed_groups: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub https: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rfc9700: Option<bool>,
        #[serde(rename = "namedServers", default, skip_serializing_if = "Option::is_none")]
        pub named_servers: Option<Vec<Answer200NamedServersItem>>,
        #[serde(rename = "defaultServerId", default, skip_serializing_if = "Option::is_none")]
        pub default_server_id: Option<String>,
        #[serde(rename = "groupOrder", default, skip_serializing_if = "Option::is_none")]
        pub group_order: Option<Vec<String>>,
    }
}

/// The request and hosted-surface worker pools of this node
pub mod get_worker_pools {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/worker-pools";
    pub const OPERATION_ID: &str = "getWorkerPools";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub node: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AnsweredBy {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NodesItemView {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(rename = "mainThread", default, skip_serializing_if = "Option::is_none")]
        pub main_thread: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(rename = "scopeText", default, skip_serializing_if = "Option::is_none")]
        pub scope_text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pools: Option<sts_model_management_components_4::WithClusteredTextIntervalSeconds>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200NodesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
        pub self_: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "stateText", default, skip_serializing_if = "Option::is_none")]
        pub state_text: Option<String>,
        #[serde(rename = "ageSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub age_seconds: Option<Option<f64>>,
        #[serde(rename = "takenAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub taken_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub view: Option<Answer200NodesItemView>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TotalsPoolsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(rename = "currentWorkers", default, skip_serializing_if = "Option::is_none")]
        pub current_workers: Option<f64>,
        #[serde(rename = "busyWorkers", default, skip_serializing_if = "Option::is_none")]
        pub busy_workers: Option<f64>,
        #[serde(rename = "freeWorkers", default, skip_serializing_if = "Option::is_none")]
        pub free_workers: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forked: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub crashed: Option<f64>,
        #[serde(rename = "failedStarts", default, skip_serializing_if = "Option::is_none")]
        pub failed_starts: Option<f64>,
        #[serde(rename = "nodesOn", default, skip_serializing_if = "Option::is_none")]
        pub nodes_on: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Totals {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<i64>,
        #[serde(rename = "nodesCounted", default, skip_serializing_if = "Option::is_none")]
        pub nodes_counted: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pools: Option<Vec<Answer200TotalsPoolsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
        pub generated_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub node: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub pid: Option<Option<i64>>,
        #[serde(rename = "mainThread", default, skip_serializing_if = "Option::is_none")]
        pub main_thread: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(rename = "scopeText", default, skip_serializing_if = "Option::is_none")]
        pub scope_text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pools: Option<sts_model_management_components_4::WithClusteredTextIntervalSeconds>,
        #[serde(rename = "answeredBy", default, skip_serializing_if = "Option::is_none")]
        pub answered_by: Option<Answer200AnsweredBy>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cluster: Option<sts_model_management_components_4::WithClusteredTextIntervalSeconds2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<Vec<Answer200NodesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<Answer200Totals>,
    }
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "rehomePerson" => Some(serde_json::from_value::<rehome_person::Body>(value.clone()).map(|_| ())),
        "countDataKeys" => Some(serde_json::from_value::<count_data_keys::Body>(value.clone()).map(|_| ())),
        "reencryptDataKeys" => Some(serde_json::from_value::<reencrypt_data_keys::Body>(value.clone()).map(|_| ())),
        "rotateDataKeys" => Some(serde_json::from_value::<rotate_data_keys::Body>(value.clone()).map(|_| ())),
        "rotateKek" => Some(serde_json::from_value::<rotate_kek::Body>(value.clone()).map(|_| ())),
        "rotateSigningKeysEmergency" => Some(serde_json::from_value::<rotate_signing_keys_emergency::Body>(value.clone()).map(|_| ())),
        "exportKey" => Some(serde_json::from_value::<export_key::Body>(value.clone()).map(|_| ())),
        "rotateSigningKeys" => Some(serde_json::from_value::<rotate_signing_keys::Body>(value.clone()).map(|_| ())),
        "setListenerApplications" => Some(serde_json::from_value::<set_listener_applications::Body>(value.clone()).map(|_| ())),
        "setListeners" => Some(serde_json::from_value::<set_listeners::Body>(value.clone()).map(|_| ())),
        "retryMailDeadLetter" => Some(serde_json::from_value::<retry_mail_dead_letter::Body>(value.clone()).map(|_| ())),
        "resetMailTemplate" => Some(serde_json::from_value::<reset_mail_template::Body>(value.clone()).map(|_| ())),
        "saveMailTemplate" => Some(serde_json::from_value::<save_mail_template::Body>(value.clone()).map(|_| ())),
        "sendMailTestMessage" => Some(serde_json::from_value::<send_mail_test_message::Body>(value.clone()).map(|_| ())),
        "sendMailVerificationLink" => Some(serde_json::from_value::<send_mail_verification_link::Body>(value.clone()).map(|_| ())),
        "collectGarbage" => Some(serde_json::from_value::<collect_garbage::Body>(value.clone()).map(|_| ())),
        "addScepHostName" => Some(serde_json::from_value::<add_scep_host_name::Body>(value.clone()).map(|_| ())),
        "createScepChallenge" => Some(serde_json::from_value::<create_scep_challenge::Body>(value.clone()).map(|_| ())),
        "deleteScepChallenge" => Some(serde_json::from_value::<delete_scep_challenge::Body>(value.clone()).map(|_| ())),
        "reissueScepRa" => Some(serde_json::from_value::<reissue_scep_ra::Body>(value.clone()).map(|_| ())),
        "removeScepHostName" => Some(serde_json::from_value::<remove_scep_host_name::Body>(value.clone()).map(|_| ())),
        "revokeScepCertificate" => Some(serde_json::from_value::<revoke_scep_certificate::Body>(value.clone()).map(|_| ())),
        "runSchedulerJob" => Some(serde_json::from_value::<run_scheduler_job::Body>(value.clone()).map(|_| ())),
        "stepDownScheduler" => Some(serde_json::from_value::<step_down_scheduler::Body>(value.clone()).map(|_| ())),
        "addScimClient" => Some(serde_json::from_value::<add_scim_client::Body>(value.clone()).map(|_| ())),
        "deliverScimClientNow" => Some(serde_json::from_value::<deliver_scim_client_now::Body>(value.clone()).map(|_| ())),
        "issueScimClientCertificate" => Some(serde_json::from_value::<issue_scim_client_certificate::Body>(value.clone()).map(|_| ())),
        "purgeScimDeadLetters" => Some(serde_json::from_value::<purge_scim_dead_letters::Body>(value.clone()).map(|_| ())),
        "reconcileScimClient" => Some(serde_json::from_value::<reconcile_scim_client::Body>(value.clone()).map(|_| ())),
        "removeScimClient" => Some(serde_json::from_value::<remove_scim_client::Body>(value.clone()).map(|_| ())),
        "retryScimDeadLetters" => Some(serde_json::from_value::<retry_scim_dead_letters::Body>(value.clone()).map(|_| ())),
        "retryScimDelivery" => Some(serde_json::from_value::<retry_scim_delivery::Body>(value.clone()).map(|_| ())),
        "testScimClient" => Some(serde_json::from_value::<test_scim_client::Body>(value.clone()).map(|_| ())),
        "updateScimClient" => Some(serde_json::from_value::<update_scim_client::Body>(value.clone()).map(|_| ())),
        "banSpiffeAgent" => Some(serde_json::from_value::<ban_spiffe_agent::Body>(value.clone()).map(|_| ())),
        "deleteSpiffeAgent" => Some(serde_json::from_value::<delete_spiffe_agent::Body>(value.clone()).map(|_| ())),
        "createSpiffeJoinToken" => Some(serde_json::from_value::<create_spiffe_join_token::Body>(value.clone()).map(|_| ())),
        "unbanSpiffeAgent" => Some(serde_json::from_value::<unban_spiffe_agent::Body>(value.clone()).map(|_| ())),
        "removeSpiffeBroker" => Some(serde_json::from_value::<remove_spiffe_broker::Body>(value.clone()).map(|_| ())),
        "setSpiffeBroker" => Some(serde_json::from_value::<set_spiffe_broker::Body>(value.clone()).map(|_| ())),
        "createSpiffeEntry" => Some(serde_json::from_value::<create_spiffe_entry::Body>(value.clone()).map(|_| ())),
        "deleteSpiffeEntry" => Some(serde_json::from_value::<delete_spiffe_entry::Body>(value.clone()).map(|_| ())),
        "updateSpiffeEntry" => Some(serde_json::from_value::<update_spiffe_entry::Body>(value.clone()).map(|_| ())),
        "removeSpiffeFederatedBundle" => Some(serde_json::from_value::<remove_spiffe_federated_bundle::Body>(value.clone()).map(|_| ())),
        "setSpiffeFederatedBundle" => Some(serde_json::from_value::<set_spiffe_federated_bundle::Body>(value.clone()).map(|_| ())),
        "rotateSpiffeAuthority" => Some(serde_json::from_value::<rotate_spiffe_authority::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getIndex", 200) => Some(serde_json::from_value::<get_index::Answer200>(value.clone()).map(|_| ())),
        ("getAccountApi", 200) => Some(serde_json::from_value::<get_account_api::Answer200>(value.clone()).map(|_| ())),
        ("getCaches", 200) => Some(serde_json::from_value::<get_caches::Answer200>(value.clone()).map(|_| ())),
        ("getCells", 200) => Some(serde_json::from_value::<get_cells::Answer200>(value.clone()).map(|_| ())),
        ("getCellPeople", 200) => Some(serde_json::from_value::<get_cell_people::Answer200>(value.clone()).map(|_| ())),
        ("rehomePerson", 200) => Some(serde_json::from_value::<rehome_person::Answer200>(value.clone()).map(|_| ())),
        ("getCryptoMetadata", 200) => Some(serde_json::from_value::<get_crypto_metadata::Answer200>(value.clone()).map(|_| ())),
        ("getDatabase", 200) => Some(serde_json::from_value::<get_database::Answer200>(value.clone()).map(|_| ())),
        ("getDebugger", 200) => Some(serde_json::from_value::<get_debugger::Answer200>(value.clone()).map(|_| ())),
        ("getEncryption", 200) => Some(serde_json::from_value::<get_encryption::Answer200>(value.clone()).map(|_| ())),
        ("countDataKeys", 200) => Some(serde_json::from_value::<count_data_keys::Answer200>(value.clone()).map(|_| ())),
        ("countDataKeys", 202) => Some(serde_json::from_value::<count_data_keys::Answer202>(value.clone()).map(|_| ())),
        ("reencryptDataKeys", 200) => Some(serde_json::from_value::<reencrypt_data_keys::Answer200>(value.clone()).map(|_| ())),
        ("reencryptDataKeys", 202) => Some(serde_json::from_value::<reencrypt_data_keys::Answer202>(value.clone()).map(|_| ())),
        ("rotateDataKeys", 200) => Some(serde_json::from_value::<rotate_data_keys::Answer200>(value.clone()).map(|_| ())),
        ("rotateDataKeys", 202) => Some(serde_json::from_value::<rotate_data_keys::Answer202>(value.clone()).map(|_| ())),
        ("rotateKek", 200) => Some(serde_json::from_value::<rotate_kek::Answer200>(value.clone()).map(|_| ())),
        ("rotateKek", 202) => Some(serde_json::from_value::<rotate_kek::Answer202>(value.clone()).map(|_| ())),
        ("getKeys", 200) => Some(serde_json::from_value::<get_keys::Answer200>(value.clone()).map(|_| ())),
        ("rotateSigningKeysEmergency", 200) => Some(serde_json::from_value::<rotate_signing_keys_emergency::Answer200>(value.clone()).map(|_| ())),
        ("rotateSigningKeysEmergency", 202) => Some(serde_json::from_value::<rotate_signing_keys_emergency::Answer202>(value.clone()).map(|_| ())),
        ("exportKey", 200) => Some(serde_json::from_value::<export_key::Answer200>(value.clone()).map(|_| ())),
        ("getKeyHistory", 200) => Some(serde_json::from_value::<get_key_history::Answer200>(value.clone()).map(|_| ())),
        ("rotateSigningKeys", 200) => Some(serde_json::from_value::<rotate_signing_keys::Answer200>(value.clone()).map(|_| ())),
        ("rotateSigningKeys", 202) => Some(serde_json::from_value::<rotate_signing_keys::Answer202>(value.clone()).map(|_| ())),
        ("getListeners", 200) => Some(serde_json::from_value::<get_listeners::Answer200>(value.clone()).map(|_| ())),
        ("setListenerApplications", 200) => Some(serde_json::from_value::<set_listener_applications::Answer200>(value.clone()).map(|_| ())),
        ("setListeners", 200) => Some(serde_json::from_value::<set_listeners::Answer200>(value.clone()).map(|_| ())),
        ("getMail", 200) => Some(serde_json::from_value::<get_mail::Answer200>(value.clone()).map(|_| ())),
        ("getMailOutbox", 200) => Some(serde_json::from_value::<get_mail_outbox::Answer200>(value.clone()).map(|_| ())),
        ("retryMailDeadLetter", 200) => Some(serde_json::from_value::<retry_mail_dead_letter::Answer200>(value.clone()).map(|_| ())),
        ("resetMailTemplate", 200) => Some(serde_json::from_value::<reset_mail_template::Answer200>(value.clone()).map(|_| ())),
        ("saveMailTemplate", 200) => Some(serde_json::from_value::<save_mail_template::Answer200>(value.clone()).map(|_| ())),
        ("sendMailTestMessage", 200) => Some(serde_json::from_value::<send_mail_test_message::Answer200>(value.clone()).map(|_| ())),
        ("sendMailVerificationLink", 200) => Some(serde_json::from_value::<send_mail_verification_link::Answer200>(value.clone()).map(|_| ())),
        ("getMalwareScanning", 200) => Some(serde_json::from_value::<get_malware_scanning::Answer200>(value.clone()).map(|_| ())),
        ("testMalwareScanning", 200) => Some(serde_json::from_value::<test_malware_scanning::Answer200>(value.clone()).map(|_| ())),
        ("getMe", 200) => Some(serde_json::from_value::<get_me::Answer200>(value.clone()).map(|_| ())),
        ("getMode", 200) => Some(serde_json::from_value::<get_mode::Answer200>(value.clone()).map(|_| ())),
        ("getNodeHealth", 200) => Some(serde_json::from_value::<get_node_health::Answer200>(value.clone()).map(|_| ())),
        ("collectGarbage", 200) => Some(serde_json::from_value::<collect_garbage::Answer200>(value.clone()).map(|_| ())),
        ("getOpenApi", 200) => Some(serde_json::from_value::<get_open_api::Answer200>(value.clone()).map(|_| ())),
        ("getScep", 200) => Some(serde_json::from_value::<get_scep::Answer200>(value.clone()).map(|_| ())),
        ("addScepHostName", 200) => Some(serde_json::from_value::<add_scep_host_name::Answer200>(value.clone()).map(|_| ())),
        ("createScepChallenge", 200) => Some(serde_json::from_value::<create_scep_challenge::Answer200>(value.clone()).map(|_| ())),
        ("deleteScepChallenge", 200) => Some(serde_json::from_value::<delete_scep_challenge::Answer200>(value.clone()).map(|_| ())),
        ("getScepMonitor", 200) => Some(serde_json::from_value::<get_scep_monitor::Answer200>(value.clone()).map(|_| ())),
        ("reissueScepRa", 200) => Some(serde_json::from_value::<reissue_scep_ra::Answer200>(value.clone()).map(|_| ())),
        ("removeScepHostName", 200) => Some(serde_json::from_value::<remove_scep_host_name::Answer200>(value.clone()).map(|_| ())),
        ("revokeScepCertificate", 200) => Some(serde_json::from_value::<revoke_scep_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getScheduler", 200) => Some(serde_json::from_value::<get_scheduler::Answer200>(value.clone()).map(|_| ())),
        ("runSchedulerJob", 200) => Some(serde_json::from_value::<run_scheduler_job::Answer200>(value.clone()).map(|_| ())),
        ("runSchedulerJob", 202) => Some(serde_json::from_value::<run_scheduler_job::Answer202>(value.clone()).map(|_| ())),
        ("stepDownScheduler", 200) => Some(serde_json::from_value::<step_down_scheduler::Answer200>(value.clone()).map(|_| ())),
        ("stepDownScheduler", 202) => Some(serde_json::from_value::<step_down_scheduler::Answer202>(value.clone()).map(|_| ())),
        ("getScim", 200) => Some(serde_json::from_value::<get_scim::Answer200>(value.clone()).map(|_| ())),
        ("getScimClients", 200) => Some(serde_json::from_value::<get_scim_clients::Answer200>(value.clone()).map(|_| ())),
        ("addScimClient", 200) => Some(serde_json::from_value::<add_scim_client::Answer200>(value.clone()).map(|_| ())),
        ("deliverScimClientNow", 200) => Some(serde_json::from_value::<deliver_scim_client_now::Answer200>(value.clone()).map(|_| ())),
        ("issueScimClientCertificate", 200) => Some(serde_json::from_value::<issue_scim_client_certificate::Answer200>(value.clone()).map(|_| ())),
        ("purgeScimDeadLetters", 200) => Some(serde_json::from_value::<purge_scim_dead_letters::Answer200>(value.clone()).map(|_| ())),
        ("reconcileScimClient", 200) => Some(serde_json::from_value::<reconcile_scim_client::Answer200>(value.clone()).map(|_| ())),
        ("removeScimClient", 200) => Some(serde_json::from_value::<remove_scim_client::Answer200>(value.clone()).map(|_| ())),
        ("retryScimDeadLetters", 200) => Some(serde_json::from_value::<retry_scim_dead_letters::Answer200>(value.clone()).map(|_| ())),
        ("retryScimDelivery", 200) => Some(serde_json::from_value::<retry_scim_delivery::Answer200>(value.clone()).map(|_| ())),
        ("testScimClient", 200) => Some(serde_json::from_value::<test_scim_client::Answer200>(value.clone()).map(|_| ())),
        ("updateScimClient", 200) => Some(serde_json::from_value::<update_scim_client::Answer200>(value.clone()).map(|_| ())),
        ("getScimMonitor", 200) => Some(serde_json::from_value::<get_scim_monitor::Answer200>(value.clone()).map(|_| ())),
        ("getSecrets", 200) => Some(serde_json::from_value::<get_secrets::Answer200>(value.clone()).map(|_| ())),
        ("getSpiffe", 200) => Some(serde_json::from_value::<get_spiffe::Answer200>(value.clone()).map(|_| ())),
        ("getSpiffeAgents", 200) => Some(serde_json::from_value::<get_spiffe_agents::Answer200>(value.clone()).map(|_| ())),
        ("banSpiffeAgent", 200) => Some(serde_json::from_value::<ban_spiffe_agent::Answer200>(value.clone()).map(|_| ())),
        ("deleteSpiffeAgent", 200) => Some(serde_json::from_value::<delete_spiffe_agent::Answer200>(value.clone()).map(|_| ())),
        ("createSpiffeJoinToken", 200) => Some(serde_json::from_value::<create_spiffe_join_token::Answer200>(value.clone()).map(|_| ())),
        ("unbanSpiffeAgent", 200) => Some(serde_json::from_value::<unban_spiffe_agent::Answer200>(value.clone()).map(|_| ())),
        ("getSpiffeBrokers", 200) => Some(serde_json::from_value::<get_spiffe_brokers::Answer200>(value.clone()).map(|_| ())),
        ("removeSpiffeBroker", 200) => Some(serde_json::from_value::<remove_spiffe_broker::Answer200>(value.clone()).map(|_| ())),
        ("setSpiffeBroker", 200) => Some(serde_json::from_value::<set_spiffe_broker::Answer200>(value.clone()).map(|_| ())),
        ("getSpiffeEntries", 200) => Some(serde_json::from_value::<get_spiffe_entries::Answer200>(value.clone()).map(|_| ())),
        ("createSpiffeEntry", 200) => Some(serde_json::from_value::<create_spiffe_entry::Answer200>(value.clone()).map(|_| ())),
        ("deleteSpiffeEntry", 200) => Some(serde_json::from_value::<delete_spiffe_entry::Answer200>(value.clone()).map(|_| ())),
        ("updateSpiffeEntry", 200) => Some(serde_json::from_value::<update_spiffe_entry::Answer200>(value.clone()).map(|_| ())),
        ("removeSpiffeFederatedBundle", 200) => Some(serde_json::from_value::<remove_spiffe_federated_bundle::Answer200>(value.clone()).map(|_| ())),
        ("setSpiffeFederatedBundle", 200) => Some(serde_json::from_value::<set_spiffe_federated_bundle::Answer200>(value.clone()).map(|_| ())),
        ("rotateSpiffeAuthority", 200) => Some(serde_json::from_value::<rotate_spiffe_authority::Answer200>(value.clone()).map(|_| ())),
        ("getStatus", 200) => Some(serde_json::from_value::<get_status::Answer200>(value.clone()).map(|_| ())),
        ("getStsMetadata", 200) => Some(serde_json::from_value::<get_sts_metadata::Answer200>(value.clone()).map(|_| ())),
        ("getWorkerPools", 200) => Some(serde_json::from_value::<get_worker_pools::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
