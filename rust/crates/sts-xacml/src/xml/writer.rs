// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The reader's inverse: a policy model written out as a XACML 3.0
//! document. A port of the writing half of `xacml/xacml_xml.js`, whose
//! output this matches byte for byte, so the PAP's editor and the ALFA
//! import store the same documents whichever runtime wrote them.
//!
//! **Two things it does not preserve**, as the Node writer did not:
//! comments and whitespace (the model does not carry them — which is why the
//! store keeps a document AS AUTHORED and saving from the editor is a
//! deliberate act), and attribute order (the schema's, not the source's).
//! Neither changes what a policy means; the round trip through the reader is
//! the test of that.
//!
//! **Element order is the schema's sequence, not a preference**, and
//! `<Target/>` is written for an absent target: a body this reader accepts
//! and somebody else's schema validator rejects is the worst of both.
//!
//! **An XPath's prefix bindings go back onto the element that uses it** —
//! only prefixed ones (a default `xmlns=` would move the XACML element out of
//! its own namespace), and only the prefixes the path uses. Dropping them is
//! the failure that made the first edit of a policy with a selector produce
//! a document whose XPath resolved nothing, silently: an empty bag, then
//! NotApplicable.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{canonical_type, types, NS_XACML};
use crate::policy::{
    CombinerParameter, Expression, ExpressionHolder, Policy, PolicyNode,
    PolicySet, ReferencedParameters, Rule, Target,
};

/// The same five entities every document this service emits is escaped
/// with (`common/helpers.js` `xmlEscape()`).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// ` name="value"`, or nothing for an absent or empty value.
fn attr(name: &str, value: Option<&str>) -> String {
    match value {
        Some(value) if !value.is_empty() => {
            format!(" {}=\"{}\"", name, escape(value))
        }
        _ => String::new(),
    }
}

fn indent(depth: usize) -> String {
    "  ".repeat(depth)
}

fn must_be_present(value: bool) -> &'static str {
    // Written ALWAYS, false included: the schema requires it.
    if value {
        " MustBePresent=\"true\""
    } else {
        " MustBePresent=\"false\""
    }
}

static PREFIX_USE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"([A-Za-z_][A-Za-z0-9_.-]*):").ok());

/// The bindings an XPath needs, from those captured at read time: prefixed
/// ones the text uses, never the XACML namespace, sorted by prefix. The test
/// is deliberately loose — a prefix matched inside a quoted string costs one
/// unused declaration, and missing one costs the policy.
fn namespace_attrs(
    namespaces: Option<&BTreeMap<String, String>>,
    used_in: &str,
) -> String {
    let Some(namespaces) = namespaces else {
        return String::new();
    };
    let used: BTreeSet<&str> = match PREFIX_USE.as_ref() {
        Some(pattern) => pattern
            .captures_iter(used_in)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect(),
        None => BTreeSet::new(),
    };
    namespaces
        .iter()
        .filter(|(prefix, uri)| {
            !prefix.is_empty()
                && used.contains(prefix.as_str())
                && uri.as_str() != NS_XACML
        })
        .map(|(prefix, uri)| attr(&format!("xmlns:{}", prefix), Some(uri)))
        .collect()
}

fn write_expression(expression: &Expression, depth: usize) -> String {
    let pad = indent(depth);
    match expression {
        Expression::Value(value) => {
            let xpath =
                canonical_type(&value.type_uri) == types::XPATH_EXPRESSION;
            let extra = if xpath {
                attr("XPathCategory", value.xpath_category.as_deref())
                    + &namespace_attrs(
                        value.namespaces.as_ref(),
                        &value.lexical,
                    )
            } else {
                String::new()
            };
            format!(
                "{}<AttributeValue{}{}>{}</AttributeValue>",
                pad,
                attr("DataType", Some(&value.type_uri)),
                extra,
                escape(&value.lexical)
            )
        }
        Expression::Designator(d) => format!(
            "{}<AttributeDesignator{}{}{}{}{}/>",
            pad,
            attr("Category", Some(&d.category)),
            attr("AttributeId", Some(&d.attribute_id)),
            attr("DataType", Some(&d.data_type)),
            attr("Issuer", d.issuer.as_deref()),
            must_be_present(d.must_be_present)
        ),
        Expression::Selector(s) => format!(
            "{}<AttributeSelector{}{}{}{}{}{}/>",
            pad,
            attr("Category", Some(&s.category)),
            attr("Path", Some(&s.path)),
            attr("DataType", Some(&s.data_type)),
            attr("ContextSelectorId", s.context_selector_id.as_deref()),
            namespace_attrs(Some(&s.namespaces), &s.path),
            must_be_present(s.must_be_present)
        ),
        Expression::Function(id) => {
            format!("{}<Function{}/>", pad, attr("FunctionId", Some(id)))
        }
        Expression::VariableRef(id) => format!(
            "{}<VariableReference{}/>",
            pad,
            attr("VariableId", Some(id))
        ),
        Expression::Apply(apply) => {
            // <Description> first: the schema's sequence puts it there.
            let described = if apply.description.is_empty() {
                String::new()
            } else {
                format!(
                    "{}<Description>{}</Description>\n",
                    indent(depth + 1),
                    escape(&apply.description)
                )
            };
            let inner = apply
                .args
                .iter()
                .map(|argument| write_expression(argument, depth + 1))
                .collect::<Vec<_>>()
                .join("\n");
            let body = if described.is_empty() && inner.is_empty() {
                String::new()
            } else {
                format!(
                    "\n{}{}{}{}",
                    described,
                    inner,
                    if inner.is_empty() { "" } else { "\n" },
                    pad
                )
            };
            format!(
                "{}<Apply{}>{}</Apply>",
                pad,
                attr("FunctionId", Some(&apply.function_id)),
                body
            )
        }
    }
}

fn write_target(target: Option<&Target>, depth: usize) -> String {
    let pad = indent(depth);
    let Some(target) = target.filter(|t| !t.any_of.is_empty()) else {
        return format!("{}<Target/>", pad);
    };
    let body = target
        .any_of
        .iter()
        .map(|any_of| {
            let all_ofs = any_of
                .all_of
                .iter()
                .map(|all_of| {
                    let matches = all_of
                        .matches
                        .iter()
                        .map(|m| {
                            format!(
                                "{}<Match{}>\n{}\n{}\n{}</Match>",
                                indent(depth + 3),
                                attr("MatchId", Some(&m.match_id)),
                                write_expression(&m.value, depth + 4),
                                write_expression(&m.reference, depth + 4),
                                indent(depth + 3)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!(
                        "{}<AllOf>\n{}\n{}</AllOf>",
                        indent(depth + 2),
                        matches,
                        indent(depth + 2)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "{}<AnyOf>\n{}\n{}</AnyOf>",
                indent(depth + 1),
                all_ofs,
                indent(depth + 1)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{}<Target>\n{}\n{}</Target>", pad, body, pad)
}

/// Obligation or advice expressions: `(wrapper, item, id attribute, on
/// attribute)`.
struct HolderNames {
    wrapper: &'static str,
    item: &'static str,
    id: &'static str,
    on: &'static str,
}

const OBLIGATIONS: HolderNames = HolderNames {
    wrapper: "ObligationExpressions",
    item: "ObligationExpression",
    id: "ObligationId",
    on: "FulfillOn",
};

const ADVICE: HolderNames = HolderNames {
    wrapper: "AdviceExpressions",
    item: "AdviceExpression",
    id: "AdviceId",
    on: "AppliesTo",
};

fn write_holders(
    holders: &[ExpressionHolder],
    depth: usize,
    names: &HolderNames,
) -> String {
    if holders.is_empty() {
        return String::new();
    }
    let pad = indent(depth);
    let body = holders
        .iter()
        .map(|holder| {
            let assignments = holder
                .assignments
                .iter()
                .map(|one| {
                    format!(
                        "{}<AttributeAssignmentExpression{}{}{}>\n{}\n{}\
                         </AttributeAssignmentExpression>",
                        indent(depth + 2),
                        attr("AttributeId", Some(&one.attribute_id)),
                        attr("Category", one.category.as_deref()),
                        attr("Issuer", one.issuer.as_deref()),
                        write_expression(&one.expression, depth + 3),
                        indent(depth + 2)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let inner = if assignments.is_empty() {
                String::new()
            } else {
                format!("\n{}\n{}", assignments, indent(depth + 1))
            };
            format!(
                "{}<{}{}{}>{}</{}>",
                indent(depth + 1),
                names.item,
                attr(names.id, Some(&holder.id)),
                attr(names.on, Some(&holder.on)),
                inner,
                names.item
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "\n{}<{}>\n{}\n{}</{}>",
        pad, names.wrapper, body, pad, names.wrapper
    )
}

/// `<PolicyDefaults>` / `<PolicySetDefaults>`, only when there is a version
/// to put in it: an empty one is not schema-valid.
fn write_defaults(
    xpath_version: Option<&str>,
    depth: usize,
    wrapper: &str,
) -> String {
    match xpath_version {
        Some(version) if !version.is_empty() => format!(
            "\n{}<{}>\n{}<XPathVersion>{}</XPathVersion>\n{}</{}>",
            indent(depth),
            wrapper,
            indent(depth + 1),
            escape(version),
            indent(depth),
            wrapper
        ),
        _ => String::new(),
    }
}

/// The combiner parameters are carried, never read: the writer's job is to
/// make sure an edit does not delete them.
fn write_parameter_list(
    parameters: &[CombinerParameter],
    depth: usize,
) -> String {
    parameters
        .iter()
        .map(|one| {
            format!(
                "{}<CombinerParameter{}>\n{}\n{}</CombinerParameter>",
                indent(depth),
                attr("ParameterName", Some(&one.name)),
                write_expression(&one.value, depth + 1),
                indent(depth)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_combiner_parameters(
    parameters: &[CombinerParameter],
    depth: usize,
) -> String {
    if parameters.is_empty() {
        return String::new();
    }
    let pad = indent(depth);
    format!(
        "\n{}<CombinerParameters>\n{}\n{}</CombinerParameters>",
        pad,
        write_parameter_list(parameters, depth + 1),
        pad
    )
}

fn write_referenced_parameters(
    groups: &[ReferencedParameters],
    depth: usize,
    element: &str,
    id_attribute: &str,
) -> String {
    let pad = indent(depth);
    groups
        .iter()
        .map(|group| {
            format!(
                "\n{}<{}{}>\n{}\n{}</{}>",
                pad,
                element,
                attr(id_attribute, Some(&group.reference)),
                write_parameter_list(&group.parameters, depth + 1),
                pad,
                element
            )
        })
        .collect()
}

fn write_description(description: &str, depth: usize) -> String {
    if description.is_empty() {
        return String::new();
    }
    format!(
        "\n{}<Description>{}</Description>",
        indent(depth),
        escape(description)
    )
}

fn write_rule(rule: &Rule, depth: usize) -> String {
    let pad = indent(depth);
    let mut body = write_description(&rule.description, depth + 1);
    body.push('\n');
    body.push_str(&write_target(rule.target.as_ref(), depth + 1));
    if let Some(condition) = &rule.condition {
        body.push_str(&format!(
            "\n{}<Condition>\n{}\n{}</Condition>",
            indent(depth + 1),
            write_expression(condition, depth + 2),
            indent(depth + 1)
        ));
    }
    body.push_str(&write_holders(&rule.obligations, depth + 1, &OBLIGATIONS));
    body.push_str(&write_holders(&rule.advice, depth + 1, &ADVICE));
    format!(
        "{}<Rule{}{}>{}\n{}</Rule>",
        pad,
        attr("RuleId", Some(&rule.id)),
        attr("Effect", Some(rule.effect.as_str())),
        body,
        pad
    )
}

fn version_or_default(version: &str) -> &str {
    if version.is_empty() {
        "1.0"
    } else {
        version
    }
}

fn namespace_declaration(with_namespace: bool) -> String {
    if with_namespace {
        format!(" xmlns=\"{}\"", NS_XACML)
    } else {
        String::new()
    }
}

fn write_policy_body(
    policy: &Policy,
    depth: usize,
    with_namespace: bool,
) -> String {
    let pad = indent(depth);
    // The schema's sequence: Description, PolicyDefaults, Target, the
    // repeatable group, then the two expression holders.
    let mut body = write_description(&policy.description, depth + 1);
    body.push_str(&write_defaults(
        policy.xpath_version.as_deref(),
        depth + 1,
        "PolicyDefaults",
    ));
    body.push('\n');
    body.push_str(&write_target(policy.target.as_ref(), depth + 1));
    body.push_str(&write_combiner_parameters(
        &policy.combiner_parameters,
        depth + 1,
    ));
    body.push_str(&write_referenced_parameters(
        &policy.rule_combiner_parameters,
        depth + 1,
        "RuleCombinerParameters",
        "RuleIdRef",
    ));
    for (id, expression) in &policy.variables {
        body.push_str(&format!(
            "\n{}<VariableDefinition{}>\n{}\n{}</VariableDefinition>",
            indent(depth + 1),
            attr("VariableId", Some(id)),
            write_expression(expression, depth + 2),
            indent(depth + 1)
        ));
    }
    for rule in &policy.rules {
        body.push('\n');
        body.push_str(&write_rule(rule, depth + 1));
    }
    body.push_str(&write_holders(&policy.obligations, depth + 1, &OBLIGATIONS));
    body.push_str(&write_holders(&policy.advice, depth + 1, &ADVICE));
    // MaxDelegationDepth is carried rather than honoured: this PDP
    // implements no administrative delegation.
    format!(
        "{}<Policy{}{}{}{}{}>{}\n{}</Policy>",
        pad,
        namespace_declaration(with_namespace),
        attr("PolicyId", Some(&policy.id)),
        attr("Version", Some(version_or_default(&policy.version))),
        attr("RuleCombiningAlgId", Some(&policy.combining_alg_id)),
        attr("MaxDelegationDepth", policy.max_delegation_depth.as_deref()),
        body,
        pad
    )
}

/// The namespace is declared on the root and nowhere else: a nested element
/// carrying its own reads as though it might be a different one.
fn write_policy_set_body(
    set: &PolicySet,
    depth: usize,
    with_namespace: bool,
) -> String {
    let pad = indent(depth);
    let mut body = write_description(&set.description, depth + 1);
    body.push_str(&write_defaults(
        set.xpath_version.as_deref(),
        depth + 1,
        "PolicySetDefaults",
    ));
    body.push('\n');
    body.push_str(&write_target(set.target.as_ref(), depth + 1));
    body.push_str(&write_combiner_parameters(
        &set.combiner_parameters,
        depth + 1,
    ));
    body.push_str(&write_referenced_parameters(
        &set.policy_combiner_parameters,
        depth + 1,
        "PolicyCombinerParameters",
        "PolicyIdRef",
    ));
    body.push_str(&write_referenced_parameters(
        &set.policy_set_combiner_parameters,
        depth + 1,
        "PolicySetCombinerParameters",
        "PolicySetIdRef",
    ));
    for child in &set.children {
        body.push('\n');
        body.push_str(&match child {
            PolicyNode::Policy(policy) => {
                write_policy_body(policy, depth + 1, false)
            }
            PolicyNode::PolicySet(nested) => {
                write_policy_set_body(nested, depth + 1, false)
            }
            PolicyNode::PolicyIdReference { reference, version } => {
                write_reference("PolicyIdReference", reference, version, depth)
            }
            PolicyNode::PolicySetIdReference { reference, version } => {
                write_reference(
                    "PolicySetIdReference",
                    reference,
                    version,
                    depth,
                )
            }
        });
    }
    body.push_str(&write_holders(&set.obligations, depth + 1, &OBLIGATIONS));
    body.push_str(&write_holders(&set.advice, depth + 1, &ADVICE));
    format!(
        "{}<PolicySet{}{}{}{}{}>{}\n{}</PolicySet>",
        pad,
        namespace_declaration(with_namespace),
        attr("PolicySetId", Some(&set.id)),
        attr("Version", Some(version_or_default(&set.version))),
        attr("PolicyCombiningAlgId", Some(&set.combining_alg_id)),
        attr("MaxDelegationDepth", set.max_delegation_depth.as_deref()),
        body,
        pad
    )
}

fn write_reference(
    element: &str,
    reference: &str,
    version: &Option<String>,
    depth: usize,
) -> String {
    format!(
        "{}<{}{}>{}</{}>",
        indent(depth + 1),
        element,
        attr("Version", version.as_deref()),
        escape(reference),
        element
    )
}

/// A Policy or PolicySet as a XACML 3.0 document, with an XML declaration.
/// A bare reference is not a document and is written as its element alone.
pub fn write_policy(node: &PolicyNode) -> String {
    let body = match node {
        PolicyNode::Policy(policy) => write_policy_body(policy, 0, true),
        PolicyNode::PolicySet(set) => write_policy_set_body(set, 0, true),
        PolicyNode::PolicyIdReference { reference, version } => {
            write_reference("PolicyIdReference", reference, version, 0)
                .trim_start()
                .to_string()
        }
        PolicyNode::PolicySetIdReference { reference, version } => {
            write_reference("PolicySetIdReference", reference, version, 0)
                .trim_start()
                .to_string()
        }
    };
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}\n", body)
}
