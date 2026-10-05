// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Static validation: the errors a policy can be refused for before any
//! request arrives. A port of `xacml/xacml_validate.js`.
//!
//! XACML is statically typed, so a policy that adds a string to an integer
//! is WRONG for every request, not for some. Five conformance cases exist
//! for this and nothing else (IIC003: a bag where a primitive is required —
//! the commonest mistake in hand-written XACML; IIC012: a non-boolean
//! Condition; IIC014: a string literal where an integer is required; IIC332
//! and IIC335: a literal substring index out of range).
//!
//! It validates the MODEL, so every syntax is held to the same check.
//!
//! **It is deliberately incomplete in one direction.** Where a type cannot
//! be determined statically (`map`'s result, `any-of`'s either-way bag) the
//! check is skipped: refusing a LEGAL policy at load protects nothing,
//! while one that goes Indeterminate at least fails closed under
//! `deny-unless-permit`. Refuse only what is certainly wrong.

use std::collections::HashSet;

use indexmap::IndexMap;

use crate::datatypes::DataTypes;
use crate::functions::{FunctionLibrary, ParamKind};
use crate::model::{canonical_type, types, Effect, XacmlError, XacmlResult};
use crate::policy::{
    Expression, ExpressionHolder, Match, Policy, PolicyNode, PolicySet, Target,
};

/// A static type: a kind, and a datatype when one can be named. A `None`
/// type inside a known kind means "this kind, of some type I cannot name",
/// which is different from not knowing at all (`Option<StaticType>::None`).
#[derive(Debug, Clone, PartialEq)]
struct StaticType {
    kind: ParamKind,
    type_uri: Option<String>,
}

struct Scope<'p> {
    variables: &'p IndexMap<String, Expression>,
    in_progress: HashSet<String>,
}

struct Checker<'p> {
    functions: &'static FunctionLibrary,
    datatypes: &'static DataTypes,
    problems: &'p mut Vec<String>,
}

fn kind_name(kind: ParamKind) -> &'static str {
    match kind {
        ParamKind::Primitive => "primitive",
        ParamKind::Bag => "bag",
        ParamKind::Function => "function",
        ParamKind::Any => "any",
    }
}

fn article(word: &str) -> &'static str {
    if word.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    }
}

impl Checker<'_> {
    /// A datatype's short name, for a message an author can act on.
    fn short(&self, uri: &str) -> String {
        self.datatypes
            .get(uri)
            .map(|row| row.name().to_string())
            .unwrap_or_else(|| uri.to_string())
    }

    fn static_type(
        &mut self,
        expression: &Expression,
        scope: &mut Scope<'_>,
    ) -> Option<StaticType> {
        match expression {
            Expression::Value(value) => {
                if self.datatypes.get(&value.type_uri).is_none() {
                    self.problems.push(format!(
                        "Unknown datatype \"{}\" on an <AttributeValue>.",
                        value.type_uri
                    ));
                    return None;
                }
                Some(StaticType {
                    kind: ParamKind::Primitive,
                    type_uri: Some(value.type_uri.clone()),
                })
            }
            // A BAG, always: the fact IIC003 turns on.
            Expression::Designator(d) => Some(StaticType {
                kind: ParamKind::Bag,
                type_uri: Some(d.data_type.clone()),
            }),
            Expression::Selector(s) => Some(StaticType {
                kind: ParamKind::Bag,
                type_uri: Some(s.data_type.clone()),
            }),
            Expression::Function(_) => Some(StaticType {
                kind: ParamKind::Function,
                type_uri: None,
            }),
            Expression::VariableRef(id) => {
                let Some(definition) = scope.variables.get(id) else {
                    self.problems.push(format!(
                        "VariableReference names \"{}\", which no \
                         VariableDefinition in this policy defines.",
                        id
                    ));
                    return None;
                };
                // A cycle was reported by whoever opened it; stop here.
                if !scope.in_progress.insert(id.clone()) {
                    return None;
                }
                let found = self.static_type(definition, scope);
                scope.in_progress.remove(id);
                found
            }
            Expression::Apply(apply) => {
                self.check_apply(&apply.function_id, &apply.args, scope)
            }
        }
    }

    /// One `<Apply>`: the function exists, the arity is right, and every
    /// argument is of the declared kind and type.
    fn check_apply(
        &mut self,
        function_id: &str,
        args: &[Expression],
        scope: &mut Scope<'_>,
    ) -> Option<StaticType> {
        let Some(definition) = self.functions.get(function_id) else {
            self.problems
                .push(format!("Unknown function \"{}\".", function_id));
            return None;
        };
        let declared = &definition.signature.args;
        let variadic = definition.signature.variadic.as_ref();
        if variadic.is_none() && args.len() != declared.len() {
            self.problems.push(format!(
                "{} takes {} argument(s) and is given {}.",
                function_id,
                declared.len(),
                args.len()
            ));
        } else if variadic.is_some() && args.len() < declared.len() {
            self.problems.push(format!(
                "{} takes at least {} argument(s) and is given {}.",
                function_id,
                declared.len(),
                args.len()
            ));
        }
        for (index, argument) in args.iter().enumerate() {
            let parameter = declared.get(index).or(variadic);
            let actual = self.static_type(argument, scope);
            let (Some(parameter), Some(actual)) = (parameter, actual) else {
                continue;
            };
            if parameter.kind == ParamKind::Any {
                continue;
            }
            if parameter.kind != actual.kind {
                let expected = kind_name(parameter.kind);
                let got = kind_name(actual.kind);
                let hint = if actual.kind == ParamKind::Bag {
                    ". An AttributeDesignator or AttributeSelector is always \
                     a bag; wrap it in the matching -one-and-only function."
                } else {
                    "."
                };
                self.problems.push(format!(
                    "{} argument {} must be {} {} and is {} {}{}",
                    function_id,
                    index + 1,
                    article(expected),
                    expected,
                    article(got),
                    got,
                    hint
                ));
                continue;
            }
            if let (Some(want), Some(have)) =
                (&parameter.type_uri, &actual.type_uri)
            {
                if canonical_type(want) != canonical_type(have) {
                    self.problems.push(format!(
                        "{} argument {} must be of type {} and is {}.",
                        function_id,
                        index + 1,
                        self.short(want),
                        self.short(have)
                    ));
                }
            }
        }
        if let Some(check) = &definition.static_check {
            check(args, self.problems);
        }
        let returns = &definition.signature.returns;
        Some(StaticType {
            kind: returns.kind,
            type_uri: returns.type_uri.clone(),
        })
    }

    /// A Condition must be exactly one boolean (section 5.28; IIC012).
    fn check_condition(
        &mut self,
        condition: &Expression,
        scope: &mut Scope<'_>,
        place: &str,
    ) {
        let Some(found) = self.static_type(condition, scope) else {
            return;
        };
        let wrong_type = found
            .type_uri
            .as_deref()
            .is_some_and(|t| canonical_type(t) != types::BOOLEAN);
        if found.kind != ParamKind::Primitive || wrong_type {
            self.problems.push(format!(
                "The <Condition> of {} must evaluate to exactly one boolean; \
                 this one evaluates to {}{}.",
                place,
                if found.kind == ParamKind::Bag {
                    "a bag of "
                } else {
                    ""
                },
                found
                    .type_uri
                    .as_deref()
                    .map(|t| self.short(t))
                    .unwrap_or_else(|| "an unknown type".into())
            ));
        }
    }

    /// A `<Match>`: a two-argument predicate returning boolean, the literal
    /// first and one value of the bag second. The Match unwraps the bag, so
    /// the ELEMENT type is what is checked.
    fn check_match(&mut self, matched: &Match, scope: &mut Scope<'_>) {
        let Some(definition) = self.functions.get(&matched.match_id) else {
            self.problems.push(format!(
                "Unknown match function \"{}\".",
                matched.match_id
            ));
            return;
        };
        let declared = &definition.signature.args;
        if declared.len() != 2 {
            self.problems.push(format!(
                "The MatchId \"{}\" names a function of {} argument(s); a \
                 <Match> needs one of two.",
                matched.match_id,
                declared.len()
            ));
        }
        if let Some(returns) = &definition.signature.returns.type_uri {
            if canonical_type(returns) != types::BOOLEAN {
                self.problems.push(format!(
                    "The MatchId \"{}\" names a function returning {}; a \
                     <Match> needs one returning boolean.",
                    matched.match_id,
                    self.short(returns)
                ));
            }
        }
        let literal = self.static_type(&matched.value, scope);
        let reference = self.static_type(&matched.reference, scope);
        if declared.len() != 2 {
            return;
        }
        let pairs = [
            (literal, &declared[0].type_uri, "The <AttributeValue>"),
            (reference, &declared[1].type_uri, "The attribute referenced"),
        ];
        for (found, want, what) in pairs {
            let (Some(found), Some(want)) = (found, want) else {
                continue;
            };
            let Some(have) = found.type_uri else {
                continue;
            };
            if canonical_type(want) != canonical_type(&have) {
                self.problems.push(format!(
                    "{} in a <Match> using \"{}\" must be of type {} and is \
                     {}.",
                    what,
                    matched.match_id,
                    self.short(want),
                    self.short(&have)
                ));
            }
        }
    }

    fn check_target(&mut self, target: Option<&Target>, scope: &mut Scope<'_>) {
        for any_of in target.iter().flat_map(|t| &t.any_of) {
            for all_of in &any_of.all_of {
                for matched in &all_of.matches {
                    self.check_match(matched, scope);
                }
            }
        }
    }

    fn check_holders(
        &mut self,
        holders: &[ExpressionHolder],
        scope: &mut Scope<'_>,
    ) {
        for holder in holders {
            if Effect::parse(&holder.on).is_none() {
                self.problems.push(format!(
                    "\"{}\" fires on \"{}\", which is neither Permit nor Deny.",
                    holder.id, holder.on
                ));
            }
            for assignment in &holder.assignments {
                self.static_type(&assignment.expression, scope);
            }
        }
    }

    fn check_policy(&mut self, policy: &Policy) {
        let mut scope = Scope {
            variables: &policy.variables,
            in_progress: HashSet::new(),
        };
        for (id, definition) in &policy.variables {
            scope.in_progress.insert(id.clone());
            self.static_type(definition, &mut scope);
            scope.in_progress.remove(id);
        }
        self.check_target(policy.target.as_ref(), &mut scope);
        for rule in &policy.rules {
            self.check_target(rule.target.as_ref(), &mut scope);
            if let Some(condition) = &rule.condition {
                self.check_condition(
                    condition,
                    &mut scope,
                    &format!("rule \"{}\"", rule.id),
                );
            }
            self.check_holders(&rule.obligations, &mut scope);
            self.check_holders(&rule.advice, &mut scope);
        }
        self.check_holders(&policy.obligations, &mut scope);
        self.check_holders(&policy.advice, &mut scope);
    }

    fn check_policy_set(&mut self, set: &PolicySet) {
        let empty = IndexMap::new();
        let mut scope = Scope {
            variables: &empty,
            in_progress: HashSet::new(),
        };
        self.check_target(set.target.as_ref(), &mut scope);
        self.check_holders(&set.obligations, &mut scope);
        self.check_holders(&set.advice, &mut scope);
        for child in &set.children {
            match child {
                PolicyNode::Policy(policy) => self.check_policy(policy),
                PolicyNode::PolicySet(inner) => self.check_policy_set(inner),
                // A reference is NOT followed: the referenced document "must
                // not be evaluated (or syntax- and type-checked) until the
                // evaluation of the PolicySet calls for" it (IIE003's own
                // Special.txt).
                _ => {}
            }
        }
    }
}

/// Every problem in a policy, without refusing it — for the PAP's editor,
/// which shows them beside the form.
pub fn problems_in(policy: &PolicyNode) -> Vec<String> {
    let mut problems = Vec::new();
    let mut checker = Checker {
        functions: FunctionLibrary::standard(),
        datatypes: DataTypes::standard(),
        problems: &mut problems,
    };
    match policy {
        PolicyNode::Policy(p) => checker.check_policy(p),
        PolicyNode::PolicySet(s) => checker.check_policy_set(s),
        _ => checker
            .problems
            .push("A policy document must be a Policy or a PolicySet.".into()),
    }
    problems
}

/// Refuses a policy with every problem listed, not just the first: fixing
/// one type error per reload is what makes static checking feel like an
/// obstacle rather than a service.
pub fn validate(policy: &PolicyNode) -> XacmlResult<()> {
    let problems = problems_in(policy);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(XacmlError::syntax(format!(
            "The policy \"{}\" does not typecheck: {}",
            policy.id(),
            problems.join(" ")
        )))
    }
}
