// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shape of a policy tree: what every reader produces and the PDP
//! evaluates. The Node engine holds these as plain objects with a `kind`
//! string; here each is a type, so a reader cannot produce a shape the PDP
//! does not know.

use std::collections::BTreeMap;

use indexmap::IndexMap;

use crate::model::Effect;

/// The six things that can appear where XACML expects an `<Expression>`.
/// The substitution group is closed.
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// An `<AttributeValue>`, carried as its LEXICAL form and declared type
    /// and parsed at evaluation, so a bad lexical form is an Indeterminate
    /// for a request rather than a policy that will not load.
    Value(AttributeValue),
    Designator(Designator),
    Selector(Selector),
    Apply(Apply),
    /// A function used as a VALUE: the first argument of a higher-order
    /// function.
    Function(String),
    VariableRef(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeValue {
    pub type_uri: String,
    pub lexical: String,
    /// For an xpathExpression only: the bindings in scope where it was
    /// written, captured because they are gone once the DOM is.
    pub namespaces: Option<BTreeMap<String, String>>,
    pub xpath_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Designator {
    pub category: String,
    pub attribute_id: String,
    pub data_type: String,
    pub issuer: Option<String>,
    pub must_be_present: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Selector {
    pub category: String,
    pub path: String,
    pub data_type: String,
    pub context_selector_id: Option<String>,
    pub must_be_present: bool,
    pub namespaces: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Apply {
    pub function_id: String,
    /// Kept so an edit through the PAP does not delete it.
    pub description: String,
    pub args: Vec<Expression>,
}

/// `Target -> AnyOf*` (all must match), `AnyOf -> AllOf*` (one must),
/// `AllOf -> Match*` (all must). The nesting reads backwards from the names.
/// An absent or empty Target matches everything, so it is an `Option` and
/// `None` is meaningful.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub any_of: Vec<AnyOf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnyOf {
    pub all_of: Vec<AllOf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AllOf {
    pub matches: Vec<Match>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub match_id: String,
    pub value: Expression,
    /// The designator or selector the value is matched against.
    pub reference: Expression,
}

/// Obligations and advice are one shape kept in two lists: a PEP MUST honour
/// an obligation and MAY ignore advice, and one list with a flag is how that
/// gets lost.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpressionHolder {
    pub id: String,
    /// FulfillOn on an obligation, AppliesTo on advice. Held as written, so
    /// the validator can refuse anything that is neither Permit nor Deny.
    pub on: String,
    pub assignments: Vec<AssignmentExpression>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssignmentExpression {
    pub attribute_id: String,
    pub category: Option<String>,
    pub issuer: Option<String>,
    pub expression: Expression,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub description: String,
    pub target: Option<Target>,
    pub condition: Option<Expression>,
    pub obligations: Vec<ExpressionHolder>,
    pub advice: Vec<ExpressionHolder>,
}

/// A `<CombinerParameter>`. Carried and never read — no standard algorithm
/// takes one — so a round trip through the PAP does not delete it.
#[derive(Debug, Clone, PartialEq)]
pub struct CombinerParameter {
    pub name: String,
    pub value: Expression,
}

/// A `<RuleCombinerParameters>` (or the Policy / PolicySet forms): the
/// parameters for one named child.
#[derive(Debug, Clone, PartialEq)]
pub struct ReferencedParameters {
    pub reference: String,
    pub parameters: Vec<CombinerParameter>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub id: String,
    pub description: String,
    pub version: String,
    pub combining_alg_id: String,
    pub xpath_version: Option<String>,
    pub target: Option<Target>,
    /// In document order, which is the order they are written back in.
    pub variables: IndexMap<String, Expression>,
    pub rules: Vec<Rule>,
    pub combiner_parameters: Vec<CombinerParameter>,
    pub rule_combiner_parameters: Vec<ReferencedParameters>,
    pub obligations: Vec<ExpressionHolder>,
    pub advice: Vec<ExpressionHolder>,
    /// Carried, not honoured: no administrative delegation is implemented.
    pub max_delegation_depth: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicySet {
    pub id: String,
    pub description: String,
    pub version: String,
    pub combining_alg_id: String,
    pub xpath_version: Option<String>,
    pub target: Option<Target>,
    pub children: Vec<PolicyNode>,
    pub combiner_parameters: Vec<CombinerParameter>,
    pub policy_combiner_parameters: Vec<ReferencedParameters>,
    pub policy_set_combiner_parameters: Vec<ReferencedParameters>,
    pub obligations: Vec<ExpressionHolder>,
    pub advice: Vec<ExpressionHolder>,
    pub max_delegation_depth: Option<String>,
}

/// A node of a policy tree: a document, or a reference to one held in the
/// repository the caller passes the PDP.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyNode {
    Policy(Policy),
    PolicySet(PolicySet),
    PolicyIdReference {
        reference: String,
        version: Option<String>,
    },
    PolicySetIdReference {
        reference: String,
        version: Option<String>,
    },
}

impl PolicyNode {
    /// The id of a Policy or PolicySet; a reference's target for the others.
    pub fn id(&self) -> &str {
        match self {
            PolicyNode::Policy(p) => &p.id,
            PolicyNode::PolicySet(s) => &s.id,
            PolicyNode::PolicyIdReference { reference, .. }
            | PolicyNode::PolicySetIdReference { reference, .. } => reference,
        }
    }

    /// The Target of a document; a reference has none of its own.
    pub fn target(&self) -> Option<&Target> {
        match self {
            PolicyNode::Policy(p) => p.target.as_ref(),
            PolicyNode::PolicySet(s) => s.target.as_ref(),
            _ => None,
        }
    }
}
