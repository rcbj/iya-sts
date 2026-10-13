// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The element-by-element walk. No XPath: the policy grammar is a small
//! tree, and walking it by name keeps what is read visible.

use std::collections::BTreeMap;

use indexmap::IndexMap;
use roxmltree::{Document, Node};

use crate::model::{
    canonical_type, types, Decision, Effect, XacmlError, XacmlResult,
};
use crate::policy::{
    AllOf, AnyOf, Apply, AssignmentExpression, AttributeValue,
    CombinerParameter, Designator, Expression, ExpressionHolder, Match, Policy,
    PolicyNode, PolicySet, ReferencedParameters, Rule, Selector, Target,
};
use crate::request::{
    Request, RequestAttribute, RequestCategory, RequestValue,
};
use crate::validate;

// ---------------------------------------------------------------------------
// Small DOM helpers. All of them match on LOCAL NAME.
// ---------------------------------------------------------------------------
fn local_name<'a>(node: &Node<'a, '_>) -> &'a str {
    node.tag_name().name()
}

fn elements<'a, 'i>(node: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(Node::is_element)
}

fn children_named<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    elements(node).filter(|c| local_name(c) == name).collect()
}

fn first_named<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    elements(node).find(|c| local_name(c) == name)
}

/// An attribute's value; an empty one counts as absent.
fn attribute(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn required(node: Node<'_, '_>, name: &str) -> XacmlResult<String> {
    attribute(node, name).ok_or_else(|| {
        XacmlError::syntax(format!(
            "<{}> is missing the required \"{}\" attribute.",
            local_name(&node),
            name
        ))
    })
}

fn boolean_attribute(node: Node<'_, '_>, name: &str, fallback: bool) -> bool {
    match attribute(node, name) {
        None => fallback,
        Some(v) => v == "true" || v == "1",
    }
}

/// The text of an element, children and all (text and CDATA).
fn text_of(node: Node<'_, '_>) -> String {
    node.descendants()
        .filter(Node::is_text)
        .filter_map(|n| n.text())
        .collect()
}

/// The namespace bindings in scope at an element, captured now because an
/// xpathExpression deep in a policy may use a prefix declared on the root,
/// and once out of the document there is nothing to resolve it against.
fn namespaces_in_scope(node: Node<'_, '_>) -> BTreeMap<String, String> {
    node.namespaces()
        .map(|ns| (ns.name().unwrap_or("").to_string(), ns.uri().to_string()))
        .filter(|(prefix, _)| prefix != "xml")
        .collect()
}

/// The `<Description>` of an element, or `""` — kept so a round trip through
/// the editor does not delete every explanation the author wrote.
fn description_of(node: Node<'_, '_>) -> String {
    first_named(node, "Description")
        .map(|d| text_of(d).trim().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Expressions. The substitution group is closed.
// ---------------------------------------------------------------------------
fn read_expression(node: Node<'_, '_>) -> XacmlResult<Expression> {
    match local_name(&node) {
        "AttributeValue" => {
            let type_uri =
                canonical_type(&required(node, "DataType")?).to_string();
            let xpath = type_uri == types::XPATH_EXPRESSION;
            Ok(Expression::Value(AttributeValue {
                lexical: text_of(node),
                namespaces: xpath.then(|| namespaces_in_scope(node)),
                xpath_category: if xpath {
                    attribute(node, "XPathCategory")
                } else {
                    None
                },
                type_uri,
            }))
        }
        "AttributeDesignator" => Ok(Expression::Designator(Designator {
            category: required(node, "Category")?,
            attribute_id: required(node, "AttributeId")?,
            data_type: canonical_type(&required(node, "DataType")?).to_string(),
            issuer: attribute(node, "Issuer"),
            // REQUIRED by the schema; a missing one is read as false, the
            // reading every implementation takes.
            must_be_present: boolean_attribute(node, "MustBePresent", false),
        })),
        "AttributeSelector" => Ok(Expression::Selector(Selector {
            category: required(node, "Category")?,
            path: required(node, "Path")?,
            data_type: canonical_type(&required(node, "DataType")?).to_string(),
            context_selector_id: attribute(node, "ContextSelectorId"),
            must_be_present: boolean_attribute(node, "MustBePresent", false),
            namespaces: namespaces_in_scope(node),
        })),
        "Apply" => {
            // <Description> is allowed inside <Apply> and is NOT an
            // argument; treating it as one would shift every argument.
            let args = elements(node)
                .filter(|c| local_name(c) != "Description")
                .map(read_expression)
                .collect::<XacmlResult<Vec<_>>>()?;
            Ok(Expression::Apply(Apply {
                function_id: required(node, "FunctionId")?,
                description: description_of(node),
                args,
            }))
        }
        "Function" => Ok(Expression::Function(required(node, "FunctionId")?)),
        "VariableReference" => {
            Ok(Expression::VariableRef(required(node, "VariableId")?))
        }
        other => Err(XacmlError::syntax(format!(
            "<{}> is not a XACML expression.",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Targets.
// ---------------------------------------------------------------------------
fn read_target(node: Option<Node<'_, '_>>) -> XacmlResult<Option<Target>> {
    let Some(node) = node else {
        return Ok(None);
    };
    let mut any_of = Vec::new();
    for any_node in children_named(node, "AnyOf") {
        let mut all_of = Vec::new();
        for all_node in children_named(any_node, "AllOf") {
            let matches = children_named(all_node, "Match")
                .into_iter()
                .map(read_match)
                .collect::<XacmlResult<Vec<_>>>()?;
            if matches.is_empty() {
                return Err(XacmlError::syntax(
                    "<AllOf> must hold at least one <Match>.",
                ));
            }
            all_of.push(AllOf { matches });
        }
        if all_of.is_empty() {
            return Err(XacmlError::syntax(
                "<AnyOf> must hold at least one <AllOf>.",
            ));
        }
        any_of.push(AnyOf { all_of });
    }
    Ok(if any_of.is_empty() {
        None
    } else {
        Some(Target { any_of })
    })
}

fn read_match(node: Node<'_, '_>) -> XacmlResult<Match> {
    let value = first_named(node, "AttributeValue").ok_or_else(|| {
        XacmlError::syntax("<Match> must hold an <AttributeValue>.")
    })?;
    let reference = first_named(node, "AttributeDesignator")
        .or_else(|| first_named(node, "AttributeSelector"))
        .ok_or_else(|| {
            XacmlError::syntax(
                "<Match> must hold an <AttributeDesignator> or an \
                 <AttributeSelector>.",
            )
        })?;
    Ok(Match {
        match_id: required(node, "MatchId")?,
        value: read_expression(value)?,
        reference: read_expression(reference)?,
    })
}

// ---------------------------------------------------------------------------
// Obligations and advice: one reader, two lists.
// ---------------------------------------------------------------------------
fn read_holders(
    parent: Node<'_, '_>,
    wrapper: &str,
    item: &str,
    id_attribute: &str,
    on_attribute: &str,
) -> XacmlResult<Vec<ExpressionHolder>> {
    let Some(container) = first_named(parent, wrapper) else {
        return Ok(Vec::new());
    };
    children_named(container, item)
        .into_iter()
        .map(|node| {
            let assignments =
                children_named(node, "AttributeAssignmentExpression")
                    .into_iter()
                    .map(|assignment| {
                        let children: Vec<_> = elements(assignment).collect();
                        if children.len() != 1 {
                            return Err(XacmlError::syntax(
                                "<AttributeAssignmentExpression> must hold \
                             exactly one expression.",
                            ));
                        }
                        Ok(AssignmentExpression {
                            attribute_id: required(assignment, "AttributeId")?,
                            category: attribute(assignment, "Category"),
                            issuer: attribute(assignment, "Issuer"),
                            expression: read_expression(children[0])?,
                        })
                    })
                    .collect::<XacmlResult<Vec<_>>>()?;
            Ok(ExpressionHolder {
                id: required(node, id_attribute)?,
                on: required(node, on_attribute)?,
                assignments,
            })
        })
        .collect()
}

fn read_obligations(
    parent: Node<'_, '_>,
) -> XacmlResult<Vec<ExpressionHolder>> {
    read_holders(
        parent,
        "ObligationExpressions",
        "ObligationExpression",
        "ObligationId",
        "FulfillOn",
    )
}

fn read_advice(parent: Node<'_, '_>) -> XacmlResult<Vec<ExpressionHolder>> {
    read_holders(
        parent,
        "AdviceExpressions",
        "AdviceExpression",
        "AdviceId",
        "AppliesTo",
    )
}

// ---------------------------------------------------------------------------
// Rules, policies and policy sets.
// ---------------------------------------------------------------------------
fn read_rule(node: Node<'_, '_>) -> XacmlResult<Rule> {
    let effect_text = required(node, "Effect")?;
    let effect = Effect::parse(&effect_text).ok_or_else(|| {
        XacmlError::syntax(format!(
            "A <Rule> Effect must be \"Permit\" or \"Deny\"; this one is \
             \"{}\".",
            effect_text
        ))
    })?;
    let condition = match first_named(node, "Condition") {
        None => None,
        Some(condition) => {
            let children: Vec<_> = elements(condition).collect();
            if children.len() != 1 {
                return Err(XacmlError::syntax(format!(
                    "<Condition> must hold exactly one expression; this one \
                     holds {}.",
                    children.len()
                )));
            }
            Some(read_expression(children[0])?)
        }
    };
    Ok(Rule {
        id: required(node, "RuleId")?,
        effect,
        description: description_of(node),
        target: read_target(first_named(node, "Target"))?,
        condition,
        obligations: read_obligations(node)?,
        advice: read_advice(node)?,
    })
}

fn read_variables(
    node: Node<'_, '_>,
) -> XacmlResult<IndexMap<String, Expression>> {
    let mut variables = IndexMap::new();
    for definition in children_named(node, "VariableDefinition") {
        let id = required(definition, "VariableId")?;
        if variables.contains_key(&id) {
            // Unique within a policy; a duplicate overwriting the first
            // would make the winner depend on document order.
            return Err(XacmlError::syntax(format!(
                "VariableId \"{}\" is defined twice in one <Policy>.",
                id
            )));
        }
        let children: Vec<_> = elements(definition).collect();
        if children.len() != 1 {
            return Err(XacmlError::syntax(
                "<VariableDefinition> must hold exactly one expression.",
            ));
        }
        variables.insert(id, read_expression(children[0])?);
    }
    Ok(variables)
}

fn read_xpath_version(node: Node<'_, '_>, wrapper: &str) -> Option<String> {
    let defaults = first_named(node, wrapper)?;
    first_named(defaults, "XPathVersion").map(|v| text_of(v).trim().to_string())
}

/// Combiner parameters: carried so an edit does not delete them; no
/// standard algorithm reads one.
fn read_parameter_list(
    node: Node<'_, '_>,
) -> XacmlResult<Vec<CombinerParameter>> {
    children_named(node, "CombinerParameter")
        .into_iter()
        .map(|one| {
            let children: Vec<_> = elements(one).collect();
            if children.len() != 1 {
                return Err(XacmlError::syntax(
                    "<CombinerParameter> must hold exactly one \
                     <AttributeValue>.",
                ));
            }
            Ok(CombinerParameter {
                name: required(one, "ParameterName")?,
                value: read_expression(children[0])?,
            })
        })
        .collect()
}

fn read_combiner_parameters(
    node: Node<'_, '_>,
) -> XacmlResult<Vec<CombinerParameter>> {
    let mut out = Vec::new();
    for group in children_named(node, "CombinerParameters") {
        out.extend(read_parameter_list(group)?);
    }
    Ok(out)
}

fn read_referenced_parameters(
    node: Node<'_, '_>,
    element: &str,
    id_attribute: &str,
) -> XacmlResult<Vec<ReferencedParameters>> {
    children_named(node, element)
        .into_iter()
        .map(|group| {
            Ok(ReferencedParameters {
                reference: required(group, id_attribute)?,
                parameters: read_parameter_list(group)?,
            })
        })
        .collect()
}

fn read_policy(node: Node<'_, '_>) -> XacmlResult<Policy> {
    let rules = children_named(node, "Rule")
        .into_iter()
        .map(read_rule)
        .collect::<XacmlResult<Vec<_>>>()?;
    let mut seen = std::collections::HashSet::new();
    for rule in &rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(XacmlError::syntax(format!(
                "RuleId \"{}\" appears twice in one <Policy>.",
                rule.id
            )));
        }
    }
    Ok(Policy {
        id: required(node, "PolicyId")?,
        description: description_of(node),
        version: attribute(node, "Version").unwrap_or_else(|| "1.0".into()),
        combining_alg_id: required(node, "RuleCombiningAlgId")?,
        xpath_version: read_xpath_version(node, "PolicyDefaults"),
        target: read_target(first_named(node, "Target"))?,
        variables: read_variables(node)?,
        rules,
        combiner_parameters: read_combiner_parameters(node)?,
        rule_combiner_parameters: read_referenced_parameters(
            node,
            "RuleCombinerParameters",
            "RuleIdRef",
        )?,
        obligations: read_obligations(node)?,
        advice: read_advice(node)?,
        max_delegation_depth: attribute(node, "MaxDelegationDepth"),
    })
}

fn read_policy_set(node: Node<'_, '_>) -> XacmlResult<PolicySet> {
    let mut children = Vec::new();
    for child in elements(node) {
        match local_name(&child) {
            "Policy" => children.push(PolicyNode::Policy(read_policy(child)?)),
            "PolicySet" => {
                children.push(PolicyNode::PolicySet(read_policy_set(child)?))
            }
            "PolicyIdReference" => {
                children.push(PolicyNode::PolicyIdReference {
                    reference: text_of(child).trim().to_string(),
                    version: attribute(child, "Version"),
                })
            }
            "PolicySetIdReference" => {
                children.push(PolicyNode::PolicySetIdReference {
                    reference: text_of(child).trim().to_string(),
                    version: attribute(child, "Version"),
                })
            }
            _ => {}
        }
    }
    Ok(PolicySet {
        id: required(node, "PolicySetId")?,
        description: description_of(node),
        version: attribute(node, "Version").unwrap_or_else(|| "1.0".into()),
        combining_alg_id: required(node, "PolicyCombiningAlgId")?,
        xpath_version: read_xpath_version(node, "PolicySetDefaults"),
        target: read_target(first_named(node, "Target"))?,
        children,
        combiner_parameters: read_combiner_parameters(node)?,
        policy_combiner_parameters: read_referenced_parameters(
            node,
            "PolicyCombinerParameters",
            "PolicyIdRef",
        )?,
        policy_set_combiner_parameters: read_referenced_parameters(
            node,
            "PolicySetCombinerParameters",
            "PolicySetIdRef",
        )?,
        obligations: read_obligations(node)?,
        advice: read_advice(node)?,
        max_delegation_depth: attribute(node, "MaxDelegationDepth"),
    })
}

fn parse_document(xml: &str) -> XacmlResult<Document<'_>> {
    Document::parse(xml).map_err(|error| {
        XacmlError::syntax(format!(
            "The document is not well-formed XML: {}",
            error
        ))
    })
}

/// Reads a policy document WITHOUT the static check — for a repository a
/// caller validates on its own schedule.
pub fn parse_policy_unchecked(xml: &str) -> XacmlResult<PolicyNode> {
    let document = parse_document(xml)?;
    let root = document.root_element();
    match local_name(&root) {
        "Policy" => Ok(PolicyNode::Policy(read_policy(root)?)),
        "PolicySet" => Ok(PolicyNode::PolicySet(read_policy_set(root)?)),
        other => Err(XacmlError::syntax(format!(
            "A policy document's root must be <Policy> or <PolicySet>; this \
             one is <{}>.",
            other
        ))),
    }
}

/// Reads a policy document and validates it. STATIC VALIDATION IS PART OF
/// LOADING, not a step a caller can forget: a policy that does not typecheck
/// is wrong for every request.
#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_policy(xml: &str) -> XacmlResult<PolicyNode> {
    let policy = parse_policy_unchecked(xml)?;
    validate::validate(&policy)?;
    Ok(policy)
}

/// Reads a `<Request>` document.
#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_request(xml: &str) -> XacmlResult<Request> {
    let document = parse_document(xml)?;
    let root = document.root_element();
    if local_name(&root) != "Request" {
        return Err(XacmlError::syntax(format!(
            "A request document's root must be <Request>; this one is <{}>.",
            local_name(&root)
        )));
    }
    read_request(root)
}

/// Reads a `<Request>` element — split out so a request nested in another
/// envelope (`POST /xacml/pip`) is read by the same code, not re-serialised.
pub fn read_request(root: Node<'_, '_>) -> XacmlResult<Request> {
    let mut categories = Vec::new();
    for node in children_named(root, "Attributes") {
        let mut attributes = Vec::new();
        for each in children_named(node, "Attribute") {
            let values = children_named(each, "AttributeValue")
                .into_iter()
                .map(|v| {
                    Ok(RequestValue {
                        type_uri: canonical_type(&required(v, "DataType")?)
                            .to_string(),
                        lexical: text_of(v),
                    })
                })
                .collect::<XacmlResult<Vec<_>>>()?;
            attributes.push(RequestAttribute {
                attribute_id: required(each, "AttributeId")?,
                issuer: attribute(each, "Issuer"),
                include_in_result: boolean_attribute(
                    each,
                    "IncludeInResult",
                    false,
                ),
                values,
            });
        }
        categories.push(RequestCategory {
            category: required(node, "Category")?,
            id: attribute(node, "id"),
            has_content: first_named(node, "Content").is_some(),
            attributes,
        });
    }
    Ok(Request {
        return_policy_id_list: boolean_attribute(
            root,
            "ReturnPolicyIdList",
            false,
        ),
        combined_decision: boolean_attribute(root, "CombinedDecision", false),
        categories,
    })
}

/// One `<Result>` of an expected Response: its decision and the identifiers
/// of its obligations — what the conformance runner compares.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedResult {
    pub decision: Option<Decision>,
    pub decision_text: String,
    pub status_code: Option<String>,
    pub obligation_ids: Vec<String>,
    pub advice_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExpectedResponse {
    pub results: Vec<ExpectedResult>,
}

fn holder_ids(
    parent: Node<'_, '_>,
    wrapper: &str,
    item: &str,
    id_attribute: &str,
) -> Vec<String> {
    first_named(parent, wrapper)
        .map(|c| {
            children_named(c, item)
                .into_iter()
                .filter_map(|n| attribute(n, id_attribute))
                .collect()
        })
        .unwrap_or_default()
}

/// Reads a `<Response>` back. Only a conformance runner needs this; it is
/// here so it reads responses the way this crate reads everything else.
pub fn parse_response(xml: &str) -> XacmlResult<ExpectedResponse> {
    let document = parse_document(xml)?;
    let root = document.root_element();
    if local_name(&root) != "Response" {
        return Err(XacmlError::syntax(format!(
            "Expected <Response>, found <{}>.",
            local_name(&root)
        )));
    }
    let results = children_named(root, "Result")
        .into_iter()
        .map(|node| {
            let decision_text = first_named(node, "Decision")
                .map(|d| text_of(d).trim().to_string())
                .unwrap_or_default();
            ExpectedResult {
                decision: Decision::from_external(&decision_text),
                decision_text,
                status_code: first_named(node, "Status")
                    .and_then(|s| first_named(s, "StatusCode"))
                    .and_then(|c| attribute(c, "Value")),
                obligation_ids: holder_ids(
                    node,
                    "Obligations",
                    "Obligation",
                    "ObligationId",
                ),
                advice_ids: holder_ids(
                    node,
                    "AssociatedAdvice",
                    "Advice",
                    "AdviceId",
                ),
            }
        })
        .collect();
    Ok(ExpectedResponse { results })
}
