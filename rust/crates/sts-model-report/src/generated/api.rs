// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

pub mod components {
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AnnouncementPageAnnouncementsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AnnouncementPage {
        /// This service's clock, in milliseconds: the `since` of the next ask.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub now: Option<f64>,
        #[serde(rename = "everyMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub every_ms: Option<Option<f64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub announcements: Option<Vec<AnnouncementPageAnnouncementsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Catalog {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sources: Option<Vec<crate::components::Source>>,
    }

    /// A run a schedule skipped: `reportNoteFailure()`.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DefinitionFailuresItem {
        /// When, in milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Definition {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The owner's subject (urn:uuid:…).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        /// The owner's display name, or username; empty for a subject this realm
        /// cannot name.
        #[serde(rename = "ownerName", default, skip_serializing_if = "Option::is_none")]
        pub owner_name: Option<String>,
        /// A five-field cron expression in UTC, or empty. The application composes
        /// it from a date-time and weekday boxes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<String>,
        #[serde(rename = "scheduleEnabled", default, skip_serializing_if = "Option::is_none")]
        pub schedule_enabled: Option<bool>,
        /// When the enabled schedule next occurs, ISO-8601 UTC; null when it is off
        /// or has no occurrence.
        #[serde(rename = "nextRunAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub next_run_at: Option<Option<String>>,
        /// The most recent occurrence the schedule has taken (queued, or skipped
        /// with a note), or null.
        #[serde(rename = "lastSlotAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_slot_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notify: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub editable: Option<bool>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<String>>,
        #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub modified_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<crate::components::QueryDocument>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parameters: Option<crate::components::ParameterBag>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<Vec<DefinitionFailuresItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DefinitionEnvelope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub definition: Option<crate::components::Definition>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DefinitionList {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub definitions: Option<Vec<crate::components::Definition>>,
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
    pub struct DefinitionWrite {
        /// What the definition is called: at most 120 characters, not only spaces.
        pub name: String,
        pub document: crate::components::QueryDocument,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parameters: Option<crate::components::ParameterBag>,
        /// A UTC cron expression, or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<String>,
        #[serde(rename = "scheduleEnabled", default, skip_serializing_if = "Option::is_none")]
        pub schedule_enabled: Option<bool>,
        /// Mail the owner when a scheduled run finishes. The message links to the
        /// job. It does not contain rows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notify: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Deleted {
        /// The definition's id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deleted: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum FieldType {
        #[serde(rename = "string")]
        String,
        #[serde(rename = "number")]
        Number,
        #[serde(rename = "boolean")]
        Boolean,
        #[serde(rename = "timestamp")]
        Timestamp,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Field {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<FieldType>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub meaning: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sort: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub group: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operators: Option<Vec<String>>,
        /// The operators the directory answers with an index, so a filter using one
        /// of them reads only the rows it names. A users query whose filter uses
        /// none, with an order or a count, or on a sealed field, reads every
        /// person: refused in sync mode (result_too_large), a job in auto mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub indexed: Option<Vec<String>>,
        /// The values whose equality the index answers, when it answers only some:
        /// users status is indexed for locked, and active is everybody else. Absent
        /// when every value is answered.
        #[serde(rename = "indexedValues", default, skip_serializing_if = "Option::is_none")]
        pub indexed_values: Option<Vec<String>>,
        /// Every value the field can hold, when it is an enumeration; the page
        /// draws a dropdown of them for equals and not equals. Absent for an open
        /// field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Filter {
        FilterLogical(crate::components::FilterLogical),
        FilterNot(Box<crate::components::FilterNot>),
        FilterIsNull(crate::components::FilterIsNull),
        FilterValue(crate::components::FilterValue),
        FilterIn(crate::components::FilterIn),
        FilterParam(crate::components::FilterParam),
    }

    /// in, with between 1 and 50 values.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FilterIn {
        pub op: String,
        pub field: String,
        pub value: Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    }

    /// isNull names the field and nothing else.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FilterIsNull {
        pub op: String,
        pub field: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum FilterLogicalOp {
        #[serde(rename = "and")]
        And,
        #[serde(rename = "or")]
        Or,
    }

    /// and or or over between 1 and 16 filters.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FilterLogical {
        pub op: FilterLogicalOp,
        pub args: Vec<Box<crate::components::Filter>>,
    }

    /// not over one filter.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FilterNot {
        pub op: String,
        pub arg: Box<crate::components::Filter>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum FilterParamOp {
        #[serde(rename = "eq")]
        Eq,
        #[serde(rename = "ne")]
        Ne,
        #[serde(rename = "lt")]
        Lt,
        #[serde(rename = "le")]
        Le,
        #[serde(rename = "gt")]
        Gt,
        #[serde(rename = "ge")]
        Ge,
        #[serde(rename = "contains")]
        Contains,
        #[serde(rename = "startsWith")]
        StartsWith,
        #[serde(rename = "in")]
        In,
    }

    /// A comparison whose value is a saved definition's parameter, named here and
    /// given when the definition runs.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FilterParam {
        pub op: FilterParamOp,
        pub field: String,
        /// The parameter's name, 1 to 64 characters, as a parameter bag's names
        /// are.
        pub param: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum FilterValueOp {
        #[serde(rename = "eq")]
        Eq,
        #[serde(rename = "ne")]
        Ne,
        #[serde(rename = "lt")]
        Lt,
        #[serde(rename = "le")]
        Le,
        #[serde(rename = "gt")]
        Gt,
        #[serde(rename = "ge")]
        Ge,
        #[serde(rename = "contains")]
        Contains,
        #[serde(rename = "startsWith")]
        StartsWith,
    }

    /// A comparison with one value: a string, a number, a boolean or null, which
    /// the field's type then decides.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FilterValue {
        pub op: FilterValueOp,
        pub field: String,
        pub value: Option<sts_model_base::unions::BoolOrNumberOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Group {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        /// The cn.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The group's own address, or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mail: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct GroupPage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub groups: Option<Vec<crate::components::Group>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IndexVersion {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stamped: Option<bool>,
        #[serde(rename = "buildInfo", default, skip_serializing_if = "Option::is_none")]
        pub build_info: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Index {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub service: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub catalog: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realms: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<IndexVersion>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum JobStatus {
        #[serde(rename = "queued")]
        Queued,
        #[serde(rename = "running")]
        Running,
        #[serde(rename = "completed")]
        Completed,
        #[serde(rename = "failed")]
        Failed,
        #[serde(rename = "cancelled")]
        Cancelled,
        #[serde(rename = "expired")]
        Expired,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Job {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<JobStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<String>,
        #[serde(rename = "submittedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub submitted_at: Option<Option<String>>,
        #[serde(rename = "completedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub completed_at: Option<Option<String>>,
        #[serde(rename = "byteSize", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub byte_size: Option<Option<i64>>,
        /// The public error token. A job that exceeded report.asyncMaxMs carries
        /// result_too_large. The body of a failed job is not partial.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub error: Option<Option<String>>,
        #[serde(rename = "definitionId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub definition_id: Option<Option<String>>,
        #[serde(rename = "definitionName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub definition_name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Vec<String>>,
        /// Why this query is a job: every-person (an auto-mode query whose filter
        /// the directory cannot answer from an index, so it has to read every
        /// person), asked (mode async, or POST /jobs), limit (auto over
        /// report.syncMaxRows), source (a source that cannot be read
        /// synchronously), run (a saved definition run by hand) or schedule.
        #[serde(rename = "queuedBecause", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub queued_because: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub query: Option<crate::components::QueryDocument>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct JobEnvelope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub job: Option<crate::components::Job>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct JobList {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jobs: Option<Vec<crate::components::Job>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub next: Option<Option<String>>,
        /// Absent on a cursor page.
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
    pub struct Me {
        /// The path of the person's own photo, or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub photo: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OpenApiDocumentInfo {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OpenApiDocument {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub openapi: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub info: Option<OpenApiDocumentInfo>,
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

    pub type ParameterBag = Option<serde_json::Map<String, serde_json::Value>>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryDocumentFormat {
        #[serde(rename = "json")]
        Json,
        #[serde(rename = "csv")]
        Csv,
        #[serde(rename = "pdf")]
        Pdf,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryDocumentMode {
        #[serde(rename = "auto")]
        Auto,
        #[serde(rename = "sync")]
        Sync,
        #[serde(rename = "async")]
        Async,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct QueryDocument {
        /// One source, by its id in the catalog: {{sources}}. An array is
        /// invalid_query.
        pub source: String,
        /// The fields, at most 64, each once. A count may name none, as three
        /// presets do.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub select: Option<Option<Vec<serde_json::Value>>>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<Box<crate::components::Filter>>,
        /// At most 8 entries, each a field and a direction, and a field once.
        #[serde(rename = "orderBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub order_by: Option<Option<Vec<serde_json::Value>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format: Option<QueryDocumentFormat>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<QueryDocumentMode>,
        /// A language tag. Omitted means the PDF chrome is English. The page sends
        /// the signed-in user's language. Filipino and Swedish are drawn. Chinese
        /// is named on an English page because the PDF font is WinAnsi.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub locale: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub aggregate: Option<Option<String>>,
        /// The fields a count groups by, at most 8, each once.
        #[serde(rename = "groupBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub group_by: Option<Option<Vec<serde_json::Value>>>,
    }

    /// A report as JSON: `Formats.jsonParts()`.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct QueryResult {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Option<serde_json::Map<String, serde_json::Value>>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub truncated: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Realm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The realm's path prefix; empty for the default realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prefix: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Realms {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub current: Option<crate::components::Realm>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub realms: Option<Option<Vec<serde_json::Value>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ScheduleDefinitionFailuresItem {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ScheduleDefinition {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(rename = "ownerName", default, skip_serializing_if = "Option::is_none")]
        pub owner_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedule: Option<String>,
        #[serde(rename = "scheduleEnabled", default, skip_serializing_if = "Option::is_none")]
        pub schedule_enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notify: Option<bool>,
        #[serde(rename = "nextRunAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub next_run_at: Option<Option<String>>,
        #[serde(rename = "lastSlotAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_slot_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failures: Option<Vec<ScheduleDefinitionFailuresItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Schedule {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub definition: Option<ScheduleDefinition>,
        /// The most recent scheduled jobs, newest first, at most five.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jobs: Option<Vec<crate::components::Job>>,
        /// How many scheduled jobs the definition has in all.
        #[serde(rename = "jobCount", default, skip_serializing_if = "Option::is_none")]
        pub job_count: Option<i64>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum SchedulePageScope {
        #[serde(rename = "mine")]
        Mine,
        #[serde(rename = "realm")]
        Realm,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SchedulePage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<SchedulePageScope>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub owner: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schedules: Option<Vec<crate::components::Schedule>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ShareWrite {
        pub groups: Vec<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum SignalPageScope {
        #[serde(rename = "realm")]
        Realm,
        #[serde(rename = "own")]
        Own,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignalPageRowsItemReactionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<bool>,
        /// Why nothing was done, or empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skipped: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub observed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ended: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignalPageRowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vocabulary: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub verified: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reactions: Option<Vec<SignalPageRowsItemReactionsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignalPage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<SignalPageScope>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub receiving: Option<bool>,
        /// Why nothing can arrive, where nothing can.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<SignalPageRowsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SourcePresetsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub document: Option<crate::components::QueryDocument>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Source {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        /// True for a source read from the directory (users, credentialHolders): a
        /// filter on it has to name a field whose `indexed` list holds the operator
        /// — a leaf of an and, or every arm of an or — or it is refused as
        /// invalid_query; the other fields narrow an indexed read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub anchored: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bounded: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub retention: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub relationships: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fields: Option<Vec<crate::components::Field>>,
        /// Predefined queries (#1110): a name and a whole query document the page
        /// offers as a starting point. Data, not a stored definition: nobody owns
        /// one and nothing runs it until somebody does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub presets: Option<Vec<SourcePresetsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SourceEnvelope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<crate::components::Source>,
    }

}

/// The report API index
pub mod get_index {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api";
    pub const OPERATION_ID: &str = "getIndex";

    pub type Answer200 = crate::components::Index;
}

/// Announcements for everybody signed in
pub mod get_announcements {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/announcements";
    pub const OPERATION_ID: &str = "getAnnouncements";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<i64>,
    }

    pub type Answer200 = crate::components::AnnouncementPage;
}

/// The report catalog
pub mod get_catalog {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/catalog";
    pub const OPERATION_ID: &str = "getCatalog";

    pub type Answer200 = crate::components::Catalog;
}

/// One report source
pub mod get_catalog_source {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/catalog/{id}";
    pub const OPERATION_ID: &str = "getCatalogSource";

    pub type Answer200 = crate::components::SourceEnvelope;
}

/// List definitions
pub mod get_definitions {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/definitions";
    pub const OPERATION_ID: &str = "getDefinitions";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
    }

    pub type Answer200 = crate::components::DefinitionList;
}

/// Create a definition
pub mod create_definition {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/definitions";
    pub const OPERATION_ID: &str = "createDefinition";

    pub type Body = crate::components::DefinitionWrite;

    pub type Answer200 = crate::components::DefinitionEnvelope;
}

/// Delete a definition
pub mod delete_definition {
    pub const METHOD: &str = "DELETE";
    pub const PATH: &str = "/report-api/definitions/{id}";
    pub const OPERATION_ID: &str = "deleteDefinition";

    pub type Answer200 = crate::components::Deleted;
}

/// Read a definition
pub mod get_definition {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/definitions/{id}";
    pub const OPERATION_ID: &str = "getDefinition";

    pub type Answer200 = crate::components::DefinitionEnvelope;
}

/// Replace a definition
pub mod replace_definition {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/definitions/{id}";
    pub const OPERATION_ID: &str = "replaceDefinition";

    pub type Body = crate::components::DefinitionWrite;

    pub type Answer200 = crate::components::DefinitionEnvelope;
}

/// Run a saved definition
pub mod run_definition {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/definitions/{id}/run";
    pub const OPERATION_ID: &str = "runDefinition";

    pub type Body = crate::components::ParameterBag;

    pub type Answer202 = crate::components::JobEnvelope;
}

/// Share a definition
pub mod share_definition {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/definitions/{id}/share";
    pub const OPERATION_ID: &str = "shareDefinition";

    pub type Body = crate::components::ShareWrite;

    pub type Answer200 = crate::components::DefinitionEnvelope;
}

/// Search the realm's groups
pub mod get_groups {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/groups";
    pub const OPERATION_ID: &str = "getGroups";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
    }

    pub type Answer200 = crate::components::GroupPage;
}

/// List jobs
pub mod get_jobs {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/jobs";
    pub const OPERATION_ID: &str = "getJobs";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
    }

    pub type Answer200 = crate::components::JobList;
}

/// Queue a job
pub mod queue_job {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/jobs";
    pub const OPERATION_ID: &str = "queueJob";

    pub type Body = crate::components::QueryDocument;

    pub type Answer202 = crate::components::JobEnvelope;
}

/// Read a job
pub mod get_job {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/jobs/{id}";
    pub const OPERATION_ID: &str = "getJob";

    pub type Answer200 = crate::components::JobEnvelope;
}

/// Cancel a job
pub mod cancel_job {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/jobs/{id}/cancel";
    pub const OPERATION_ID: &str = "cancelJob";

    pub type Answer200 = crate::components::JobEnvelope;
}

/// Download a result
pub mod get_job_result {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/jobs/{id}/result";
    pub const OPERATION_ID: &str = "getJobResult";

    pub type Answer200 = crate::components::QueryResult;
}

/// What the user menu draws
pub mod get_me {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/me";
    pub const OPERATION_ID: &str = "getMe";

    pub type Answer200 = crate::components::Me;
}

/// This document
pub mod get_open_api {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/openapi.json";
    pub const OPERATION_ID: &str = "getOpenApi";

    pub type Answer200 = crate::components::OpenApiDocument;
}

/// Run a query
pub mod run_query {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/report-api/queries";
    pub const OPERATION_ID: &str = "runQuery";

    pub type Body = crate::components::QueryDocument;

    pub type Answer200 = crate::components::QueryResult;

    pub type Answer202 = crate::components::JobEnvelope;
}

/// The trust realms
pub mod get_realms {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/realms";
    pub const OPERATION_ID: &str = "getRealms";

    pub type Answer200 = crate::components::Realms;
}

/// The scheduled definitions and their runs
pub mod get_schedules {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/schedules";
    pub const OPERATION_ID: &str = "getSchedules";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
    }

    pub type Answer200 = crate::components::SchedulePage;
}

/// This application's Shared Signals inbox
pub mod get_signals {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/report-api/signals";
    pub const OPERATION_ID: &str = "getSignals";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
    }

    pub type Answer200 = crate::components::SignalPage;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "createDefinition" => Some(serde_json::from_value::<create_definition::Body>(value.clone()).map(|_| ())),
        "replaceDefinition" => Some(serde_json::from_value::<replace_definition::Body>(value.clone()).map(|_| ())),
        "runDefinition" => Some(serde_json::from_value::<run_definition::Body>(value.clone()).map(|_| ())),
        "shareDefinition" => Some(serde_json::from_value::<share_definition::Body>(value.clone()).map(|_| ())),
        "queueJob" => Some(serde_json::from_value::<queue_job::Body>(value.clone()).map(|_| ())),
        "runQuery" => Some(serde_json::from_value::<run_query::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getIndex", 200) => Some(serde_json::from_value::<get_index::Answer200>(value.clone()).map(|_| ())),
        ("getAnnouncements", 200) => Some(serde_json::from_value::<get_announcements::Answer200>(value.clone()).map(|_| ())),
        ("getCatalog", 200) => Some(serde_json::from_value::<get_catalog::Answer200>(value.clone()).map(|_| ())),
        ("getCatalogSource", 200) => Some(serde_json::from_value::<get_catalog_source::Answer200>(value.clone()).map(|_| ())),
        ("getDefinitions", 200) => Some(serde_json::from_value::<get_definitions::Answer200>(value.clone()).map(|_| ())),
        ("createDefinition", 200) => Some(serde_json::from_value::<create_definition::Answer200>(value.clone()).map(|_| ())),
        ("deleteDefinition", 200) => Some(serde_json::from_value::<delete_definition::Answer200>(value.clone()).map(|_| ())),
        ("getDefinition", 200) => Some(serde_json::from_value::<get_definition::Answer200>(value.clone()).map(|_| ())),
        ("replaceDefinition", 200) => Some(serde_json::from_value::<replace_definition::Answer200>(value.clone()).map(|_| ())),
        ("runDefinition", 202) => Some(serde_json::from_value::<run_definition::Answer202>(value.clone()).map(|_| ())),
        ("shareDefinition", 200) => Some(serde_json::from_value::<share_definition::Answer200>(value.clone()).map(|_| ())),
        ("getGroups", 200) => Some(serde_json::from_value::<get_groups::Answer200>(value.clone()).map(|_| ())),
        ("getJobs", 200) => Some(serde_json::from_value::<get_jobs::Answer200>(value.clone()).map(|_| ())),
        ("queueJob", 202) => Some(serde_json::from_value::<queue_job::Answer202>(value.clone()).map(|_| ())),
        ("getJob", 200) => Some(serde_json::from_value::<get_job::Answer200>(value.clone()).map(|_| ())),
        ("cancelJob", 200) => Some(serde_json::from_value::<cancel_job::Answer200>(value.clone()).map(|_| ())),
        ("getJobResult", 200) => Some(serde_json::from_value::<get_job_result::Answer200>(value.clone()).map(|_| ())),
        ("getMe", 200) => Some(serde_json::from_value::<get_me::Answer200>(value.clone()).map(|_| ())),
        ("getOpenApi", 200) => Some(serde_json::from_value::<get_open_api::Answer200>(value.clone()).map(|_| ())),
        ("runQuery", 200) => Some(serde_json::from_value::<run_query::Answer200>(value.clone()).map(|_| ())),
        ("runQuery", 202) => Some(serde_json::from_value::<run_query::Answer202>(value.clone()).map(|_| ())),
        ("getRealms", 200) => Some(serde_json::from_value::<get_realms::Answer200>(value.clone()).map(|_| ())),
        ("getSchedules", 200) => Some(serde_json::from_value::<get_schedules::Answer200>(value.clone()).map(|_| ())),
        ("getSignals", 200) => Some(serde_json::from_value::<get_signals::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
