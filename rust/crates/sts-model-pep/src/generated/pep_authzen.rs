// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/pep/ (#1830) by models/lib/pep_lib.mjs, through
// models/lib/rust_lib.mjs (#444, D15). Do not edit: change the model and
// run tests/tools/regenerate-pep-model.sh. tests/model_pep.js fails when
// this differs.

pub mod components {
    /// Unknown members are ignored.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Action {
        pub name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub properties: Option<crate::pep_authzen::components::Properties>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Advice {
        pub id: String,
        pub attributes: Vec<crate::pep_authzen::components::AdviceAttribute>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AdviceAttribute {
        pub id: String,
        /// The value's lexical form.
        pub value: String,
    }

    /// application names the application asked about, one of the caller's; required
    /// when the caller is scoped to more than one (400 STS-AUTHZEN-0027), refused
    /// when not one of them (403 STS-AUTHZEN-0025). Every other member is a
    /// catalogue property, as in Properties.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Context {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum DecisionContextXacmlDecision {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
        #[serde(rename = "NotApplicable")]
        NotApplicable,
        #[serde(rename = "Indeterminate")]
        Indeterminate,
    }

    /// Decided here: present only when the realm's authzen.returnReasons is on,
    /// holding xacml_decision and reason_admin, and undischargeable_obligations and
    /// advice when not empty. Forwarded to the service (an application enforcing
    /// fine-grained authorization): the service's context, whole, whatever
    /// returnReasons says. On a batch item that failed: error alone.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct DecisionContext {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub xacml_decision: Option<DecisionContextXacmlDecision>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason_admin: Option<crate::pep_authzen::components::ReasonAdmin>,
        /// Obligation ids that made a Permit false (STS-AUTHZEN-0029).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub undischargeable_obligations: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub advice: Option<Vec<crate::pep_authzen::components::Advice>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<crate::pep_authzen::components::ErrorDetail>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Error {
        pub error: crate::pep_authzen::components::ErrorDetail,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ErrorDetail {
        /// The HTTP status again.
        pub status: i64,
        pub message: String,
    }

    /// One evaluation: each entity it carries replaces the default whole.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct EvaluationItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<crate::pep_authzen::components::Subject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<crate::pep_authzen::components::Action>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<crate::pep_authzen::components::Resource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<crate::pep_authzen::components::Context>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    /// Members other than these four are ignored. Refusals are 400: not an object
    /// STS-AUTHZEN-0001, a missing entity or member 0002, a wrong type 0003, and
    /// the catalogue's 0004 to 0008.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct EvaluationRequest {
        pub subject: crate::pep_authzen::components::Subject,
        pub action: crate::pep_authzen::components::Action,
        pub resource: crate::pep_authzen::components::Resource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<crate::pep_authzen::components::Context>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct EvaluationResponse {
        /// True only on a Permit with nothing undischargeable; decided deny-biased.
        /// A failed batch item is false with context.error.
        pub decision: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<crate::pep_authzen::components::DecisionContext>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum EvaluationsOptionsEvaluationsSemantic {
        #[serde(rename = "execute_all")]
        ExecuteAll,
        #[serde(rename = "deny_on_first_deny")]
        DenyOnFirstDeny,
        #[serde(rename = "permit_on_first_permit")]
        PermitOnFirstPermit,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct EvaluationsOptions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evaluations_semantic: Option<EvaluationsOptionsEvaluationsSemantic>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    /// The defaults, merged into each item; with no items, the defaults are one
    /// evaluation answered as the single endpoint answers. More than the realm's
    /// authzen.maxEvaluations items is 400 STS-AUTHZEN-0038; a body over
    /// authzen.maxBodyBytes 400 STS-AUTHZEN-0037; an unknown semantic 0036.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct EvaluationsRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<crate::pep_authzen::components::Subject>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<crate::pep_authzen::components::Action>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<crate::pep_authzen::components::Resource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<crate::pep_authzen::components::Context>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub evaluations: Option<Vec<crate::pep_authzen::components::EvaluationItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub options: Option<crate::pep_authzen::components::EvaluationsOptions>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    /// In request order; under deny_on_first_deny or permit_on_first_permit it ends
    /// at the item that stopped it.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct EvaluationsResponse {
        pub evaluations: Vec<crate::pep_authzen::components::EvaluationResponse>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Metadata {
        /// The identifier in force (the managed authzenPdpIdentifier, else
        /// PEP_AUTHZEN_PDP_IDENTIFIER), else https://<authority> of an HTTPS
        /// request: its Host header, or over HTTP/2 the :authority it sent.
        pub policy_decision_point: String,
        pub access_evaluation_endpoint: String,
        /// Only while the realm's authzen.batchEnabled is on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub access_evaluations_endpoint: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NotFound {
        pub error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }

    pub type Properties = serde_json::Map<String, serde_json::Value>;

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReasonAdmin {
        pub en: String,
    }

    /// Unknown members are ignored.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Resource {
        #[serde(rename = "type")]
        pub type_: String,
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub properties: Option<crate::pep_authzen::components::Properties>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    /// Unknown members are ignored.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Subject {
        #[serde(rename = "type")]
        pub type_: String,
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub properties: Option<crate::pep_authzen::components::Properties>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

}

/// PDP metadata (AuthZEN 1.0 section 9)
pub mod get_authzen_configuration {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/.well-known/authzen-configuration";
    pub const OPERATION_ID: &str = "getAuthzenConfiguration";

    pub type Answer200 = crate::pep_authzen::components::Metadata;
}

/// Access evaluation (AuthZEN 1.0 section 6)
pub mod post_evaluation {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/access/v1/evaluation";
    pub const OPERATION_ID: &str = "postEvaluation";

    pub type Body = crate::pep_authzen::components::EvaluationRequest;

    pub type Answer200 = crate::pep_authzen::components::EvaluationResponse;
}

/// Access evaluations (AuthZEN 1.0 section 7)
pub mod post_evaluations {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/access/v1/evaluations";
    pub const OPERATION_ID: &str = "postEvaluations";

    pub type Body = crate::pep_authzen::components::EvaluationsRequest;

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200 {
        EvaluationsResponse(crate::pep_authzen::components::EvaluationsResponse),
        EvaluationResponse(crate::pep_authzen::components::EvaluationResponse),
    }
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "postEvaluation" => Some(serde_json::from_value::<post_evaluation::Body>(value.clone()).map(|_| ())),
        "postEvaluations" => Some(serde_json::from_value::<post_evaluations::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getAuthzenConfiguration", 200) => Some(serde_json::from_value::<get_authzen_configuration::Answer200>(value.clone()).map(|_| ())),
        ("postEvaluation", 200) => Some(serde_json::from_value::<post_evaluation::Answer200>(value.clone()).map(|_| ())),
        ("postEvaluations", 200) => Some(serde_json::from_value::<post_evaluations::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
