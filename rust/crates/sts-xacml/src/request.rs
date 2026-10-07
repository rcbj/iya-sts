// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A decision request, and the PDP's answer.
//!
//! A request is FLAT on purpose: a list of categories, each a list of
//! attributes, each a bag of lexical values. A request may carry the same
//! category twice (the Multiple Decision Profile's scheme 2.3), so indexing
//! it by category on the way in would lose one.

use crate::model::{Decision, StatusCode};
use crate::value::Value;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Request {
    pub return_policy_id_list: bool,
    pub combined_decision: bool,
    pub categories: Vec<RequestCategory>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestCategory {
    pub category: String,
    pub id: Option<String>,
    /// Whether the category carried a `<Content>`. Nothing here evaluates
    /// XPath over it, so its presence is all that is kept.
    pub has_content: bool,
    pub attributes: Vec<RequestAttribute>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestAttribute {
    pub attribute_id: String,
    pub issuer: Option<String>,
    pub include_in_result: bool,
    pub values: Vec<RequestValue>,
}

/// A value as the request carried it: declared type and lexical form,
/// parsed only when a designator asks for it at that type.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestValue {
    pub type_uri: String,
    pub lexical: String,
}

/// Why there is no decision, when there is none.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub code: StatusCode,
    pub message: Option<String>,
}

impl Status {
    pub fn ok() -> Status {
        Status {
            code: StatusCode::Ok,
            message: None,
        }
    }
}

/// One attribute of a fired obligation or advice, resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedAssignment {
    pub attribute_id: String,
    pub category: Option<String>,
    pub issuer: Option<String>,
    pub type_uri: String,
    pub value: Value,
    pub lexical: String,
}

/// An obligation or advice that fired, with its assignments resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedObligation {
    pub id: String,
    pub assignments: Vec<ResolvedAssignment>,
}

/// A policy or policy set that turned out to be applicable.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyIdentifier {
    pub is_policy_set: bool,
    pub id: String,
    pub version: String,
}

/// The PDP's answer. `decision` is always one of the four external values.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub decision: Decision,
    pub status: Status,
    pub obligations: Vec<ResolvedObligation>,
    pub advice: Vec<ResolvedObligation>,
    pub policy_identifiers: Vec<PolicyIdentifier>,
}
