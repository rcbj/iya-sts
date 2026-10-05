// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Policy Decision Point: a request and a policy in, a decision out. A
//! port of `xacml/xacml_pdp.js`.
//!
//! It knows nothing about XML or HTTP. The only thing it reaches outside
//! itself for is an ATTRIBUTE, through an [`AttributeResolver`] (the PIP),
//! which is what lets the conformance suite drive the whole engine with no
//! service at all.
//!
//! **The four things a PDP gets wrong, in the order they cost the most:**
//!
//! 1. Collapsing the extended Indeterminate values — folded ONCE, at the
//!    bottom of [`Pdp::evaluate`].
//! 2. Treating a missing attribute as false. A designator that finds nothing
//!    is an EMPTY BAG; only `MustBePresent` and the function it is handed
//!    decide what that means.
//! 3. Letting a Target's Indeterminate become a No-match. The rule under it
//!    is then `Indeterminate{Effect}`, which means a Deny was possible.
//! 4. Propagating obligations from an Indeterminate (section 7.18).
//!
//! Evaluation is a hot path, so its functions carry no `instrument`
//! attribute (rust/DESIGN.md section 4.5); the entry point does.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;

use crate::combining::{Combination, CombiningAlgorithms};
use crate::datatypes::{civil_from_days, DataTypes};
use crate::functions::{Body, FunctionLibrary, LazyCall};
use crate::model::{
    attribute, canonical_type, category, policy_alg, types, Bag, Decision,
    Effect, MatchResult, StatusCode, XacmlError, XacmlResult,
};
use crate::policy::{
    AllOf, AnyOf, Designator, Expression, ExpressionHolder, Match, Policy,
    PolicyNode, PolicySet, Rule, Target,
};
use crate::request::{
    PolicyIdentifier, Request, ResolvedAssignment, ResolvedObligation,
    Response, Status,
};
use crate::value::{Temporal, TemporalShape, Value};

/// The PIP: consulted for a designator only when the request carried
/// nothing for it, because what the PEP asserted about THIS request wins
/// over what the directory holds about the world.
pub trait AttributeResolver {
    fn resolve(&self, designator: &Designator) -> Vec<Value>;
}

/// The documents a `PolicyIdReference` may name, by PolicyId — the Policy
/// Retrieval Point.
pub type Repository = HashMap<String, PolicyNode>;

/// Everything a decision may be given besides the policy and the request.
#[derive(Default)]
pub struct EvaluationOptions<'a> {
    pub resolver: Option<&'a dyn AttributeResolver>,
    pub repository: Option<&'a Repository>,
    /// The instant the three `current-*` attributes are supplied from;
    /// "now" when absent. Fixed for the whole decision, so two references to
    /// `current-time` cannot straddle a second boundary.
    pub now: Option<SystemTime>,
}

/// One node's result on the way up the tree.
#[derive(Debug, Clone)]
pub struct NodeResult {
    pub decision: Decision,
    pub status: Option<Status>,
    pub obligations: Vec<ResolvedObligation>,
    pub advice: Vec<ResolvedObligation>,
}

impl NodeResult {
    fn of(decision: Decision) -> NodeResult {
        NodeResult {
            decision,
            status: None,
            obligations: Vec::new(),
            advice: Vec::new(),
        }
    }

    fn with_status(
        decision: Decision,
        error: Option<&XacmlError>,
    ) -> NodeResult {
        NodeResult {
            status: error.map(|e| Status {
                code: e.status,
                message: Some(e.message.clone()),
            }),
            ..NodeResult::of(decision)
        }
    }

    fn syntax(decision: Decision, message: String) -> NodeResult {
        NodeResult {
            status: Some(Status {
                code: StatusCode::SyntaxError,
                message: Some(message),
            }),
            ..NodeResult::of(decision)
        }
    }
}

/// A policy's variables: evaluated at most once per decision (so a variable
/// cannot produce two different bags within one), with cycle detection —
/// a `VariableReference` may name a later definition, so a chain can loop,
/// and the failure must be an Indeterminate rather than a stack overflow.
struct Variables<'p> {
    definitions: &'p IndexMap<String, Expression>,
    values: RefCell<HashMap<String, Bag>>,
    in_progress: RefCell<HashSet<String>>,
}

impl<'p> Variables<'p> {
    fn new(definitions: &'p IndexMap<String, Expression>) -> Variables<'p> {
        Variables {
            definitions,
            values: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(HashSet::new()),
        }
    }
}

/// One decision's state.
struct Context<'a> {
    request: &'a Request,
    resolver: Option<&'a dyn AttributeResolver>,
    repository: Option<&'a Repository>,
    now: SystemTime,
    applicable: RefCell<Vec<PolicyIdentifier>>,
}

/// A child of a policy set once references are resolved.
enum Child<'a> {
    Node(&'a PolicyNode),
    Unresolved,
}

impl<'a> Child<'a> {
    fn target(&self) -> Option<&'a Target> {
        match self {
            Child::Node(node) => node.target(),
            Child::Unresolved => None,
        }
    }
}

/// The PDP. Stateless: the function library, datatypes and combining
/// algorithms are the standard tables, held by reference.
pub struct Pdp {
    datatypes: &'static DataTypes,
    functions: &'static FunctionLibrary,
    combiners: &'static CombiningAlgorithms,
}

impl Default for Pdp {
    fn default() -> Pdp {
        Pdp::new()
    }
}

impl Pdp {
    pub fn new() -> Pdp {
        Pdp {
            datatypes: DataTypes::standard(),
            functions: FunctionLibrary::standard(),
            combiners: CombiningAlgorithms::standard(),
        }
    }

    /// Decides a request against a policy tree. Never fails: a failure that
    /// escapes the tree is an Indeterminate carrying its message, because a
    /// PDP that crashes is a PDP that fails open somewhere upstream.
    #[tracing::instrument(level = "debug", skip_all, fields(policy = policy.id()))]
    pub fn evaluate(
        &self,
        policy: &PolicyNode,
        request: &Request,
        options: &EvaluationOptions<'_>,
    ) -> Response {
        let context = Context {
            request,
            resolver: options.resolver,
            repository: options.repository,
            now: options.now.unwrap_or_else(SystemTime::now),
            applicable: RefCell::new(Vec::new()),
        };
        let result = match self.evaluate_node(policy, &context) {
            Ok(result) => result,
            Err(error) => {
                NodeResult::with_status(Decision::Indeterminate, Some(&error))
            }
        };
        tracing::debug!(decision = %result.decision, "decided");
        let identifiers = if request.return_policy_id_list {
            context.applicable.into_inner()
        } else {
            Vec::new()
        };
        Response {
            // THE one place the extended values are folded back.
            decision: result.decision.external(),
            status: result.status.unwrap_or_else(Status::ok),
            obligations: result.obligations,
            advice: result.advice,
            policy_identifiers: identifiers,
        }
    }

    fn evaluate_node(
        &self,
        node: &PolicyNode,
        context: &Context<'_>,
    ) -> XacmlResult<NodeResult> {
        match node {
            PolicyNode::Policy(policy) => self.evaluate_policy(policy, context),
            PolicyNode::PolicySet(set) => {
                self.evaluate_policy_set(set, context)
            }
            other => Ok(NodeResult::syntax(
                Decision::IndeterminateDP,
                format!(
                    "Cannot evaluate an unresolved reference to \"{}\".",
                    other.id()
                ),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Attribute resolution: the request, then the PIP, then — for the three
    // environment attributes only — the clock.
    // -----------------------------------------------------------------------
    fn resolve_designator(
        &self,
        designator: &Designator,
        context: &Context<'_>,
    ) -> XacmlResult<Bag> {
        let mut values = Vec::new();
        for cat in &context.request.categories {
            if cat.category != designator.category {
                continue;
            }
            for attr in &cat.attributes {
                if attr.attribute_id != designator.attribute_id {
                    continue;
                }
                // The Issuer is a FILTER only when the designator names one;
                // without one it matches whatever the issuer.
                if let Some(issuer) = &designator.issuer {
                    if attr.issuer.as_ref() != Some(issuer) {
                        continue;
                    }
                }
                for value in &attr.values {
                    if canonical_type(&value.type_uri) != designator.data_type {
                        continue;
                    }
                    values.push(
                        self.datatypes
                            .parse(&designator.data_type, &value.lexical)?,
                    );
                }
            }
        }
        if values.is_empty() {
            if let Some(resolver) = context.resolver {
                values.extend(resolver.resolve(designator));
            }
        }
        if values.is_empty() {
            if let Some(value) = environment_attribute(designator, context.now)
            {
                values.push(value);
            }
        }
        if values.is_empty() && designator.must_be_present {
            // The ONLY place an empty bag becomes an error, and only because
            // the policy asked for it to.
            return Err(XacmlError::missing_attribute(format!(
                "The attribute \"{}\" in category \"{}\" is not present, and \
                 the policy requires it (MustBePresent=\"true\").",
                designator.attribute_id, designator.category
            )));
        }
        Ok(Bag::new(&designator.data_type, values))
    }

    // -----------------------------------------------------------------------
    // Expressions. Always a BAG.
    // -----------------------------------------------------------------------
    fn evaluate_expression(
        &self,
        expression: &Expression,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> XacmlResult<Bag> {
        match expression {
            Expression::Value(value) => {
                let parsed =
                    self.datatypes.parse(&value.type_uri, &value.lexical)?;
                Ok(Bag::singleton(&value.type_uri, parsed))
            }
            Expression::Designator(designator) => {
                self.resolve_designator(designator, context)
            }
            // Not silently empty: an empty bag is an ordinary result a policy
            // may be written to expect.
            Expression::Selector(_) => Err(XacmlError::processing(
                "AttributeSelector is not evaluable without XPath support \
                 over the request <Content>.",
            )),
            Expression::VariableRef(id) => {
                self.resolve_variable(id, context, variables)
            }
            Expression::Function(id) => Err(XacmlError::syntax(format!(
                "<Function FunctionId=\"{}\"/> is only valid as the first \
                 argument of a higher-order function.",
                id
            ))),
            Expression::Apply(apply) => {
                let definition = self
                    .functions
                    .get(&apply.function_id)
                    .ok_or_else(|| {
                        XacmlError::syntax(format!(
                            "Unknown function \"{}\".",
                            apply.function_id
                        ))
                    })?;
                if let Body::Lazy(body) = &definition.body {
                    let evaluate = |child: &Expression| {
                        self.evaluate_expression(child, context, variables)
                    };
                    return body(&LazyCall {
                        args: &apply.args,
                        evaluate: &evaluate,
                        library: self.functions,
                    });
                }
                let bags = apply
                    .args
                    .iter()
                    .map(|a| self.evaluate_expression(a, context, variables))
                    .collect::<XacmlResult<Vec<Bag>>>()?;
                self.functions.invoke(definition, &bags)
            }
        }
    }

    fn resolve_variable(
        &self,
        id: &str,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> XacmlResult<Bag> {
        let unknown = || {
            XacmlError::syntax(format!(
                "VariableReference names \"{}\", which no VariableDefinition \
                 in this policy defines.",
                id
            ))
        };
        let variables = variables.ok_or_else(unknown)?;
        let definition = variables.definitions.get(id).ok_or_else(unknown)?;
        if let Some(value) = variables.values.borrow().get(id) {
            return Ok(value.clone());
        }
        if !variables.in_progress.borrow_mut().insert(id.to_string()) {
            return Err(XacmlError::syntax(format!(
                "VariableDefinition \"{}\" refers to itself, directly or \
                 through another variable.",
                id
            )));
        }
        let result =
            self.evaluate_expression(definition, context, Some(variables));
        // Cleared whether or not it failed, so a variable that was
        // Indeterminate once is retried rather than reported as cyclic.
        variables.in_progress.borrow_mut().remove(id);
        let value = result?;
        variables
            .values
            .borrow_mut()
            .insert(id.to_string(), value.clone());
        Ok(value)
    }

    // -----------------------------------------------------------------------
    // Targets. The quantifier flips at each level.
    // -----------------------------------------------------------------------
    fn evaluate_match(
        &self,
        matched: &Match,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> XacmlResult<MatchResult> {
        let definition =
            self.functions.get(&matched.match_id).ok_or_else(|| {
                XacmlError::syntax(format!(
                    "Unknown match function \"{}\".",
                    matched.match_id
                ))
            })?;
        let attribute_bag =
            self.evaluate_expression(&matched.reference, context, variables)?;
        let literal =
            self.evaluate_expression(&matched.value, context, variables)?;
        // The function against the literal and EACH value in the bag; a
        // match if any is true. One value failing does not sink the Match:
        // its error matters only when no other value matched.
        let mut first_error = None;
        for value in &attribute_bag.values {
            let args = [
                literal.clone(),
                Bag::singleton(&attribute_bag.type_uri, value.clone()),
            ];
            match self.functions.invoke(definition, &args) {
                Ok(result) => {
                    if result.values.len() == 1
                        && result.values[0] == Value::Boolean(true)
                    {
                        return Ok(MatchResult::Match);
                    }
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(MatchResult::NoMatch),
        }
    }

    /// A Target's result, and the first error behind an Indeterminate one
    /// (whose status is what makes the enclosing decision say
    /// `missing-attribute` rather than `processing-error`).
    fn evaluate_target(
        &self,
        target: Option<&Target>,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> (MatchResult, Option<XacmlError>) {
        let Some(target) = target else {
            // An absent or empty Target matches everything (section 7.6).
            return (MatchResult::Match, None);
        };
        let mut error = None;
        for any_of in &target.any_of {
            match self.evaluate_any_of(any_of, context, variables) {
                // A conjunction: one No-match settles it, whatever the rest.
                (MatchResult::NoMatch, _) => {
                    return (MatchResult::NoMatch, None)
                }
                (MatchResult::Indeterminate, e) => {
                    if error.is_none() {
                        error = e;
                    }
                    if error.is_none() {
                        error = Some(XacmlError::processing(
                            "A <Target> could not be evaluated.",
                        ));
                    }
                }
                (MatchResult::Match, _) => {}
            }
        }
        match error {
            Some(e) => (MatchResult::Indeterminate, Some(e)),
            None => (MatchResult::Match, None),
        }
    }

    fn evaluate_any_of(
        &self,
        any_of: &AnyOf,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> (MatchResult, Option<XacmlError>) {
        let mut error = None;
        let mut indeterminate = false;
        for all_of in &any_of.all_of {
            match self.evaluate_all_of(all_of, context, variables) {
                (MatchResult::Match, _) => return (MatchResult::Match, None),
                (MatchResult::Indeterminate, e) => {
                    indeterminate = true;
                    if error.is_none() {
                        error = e;
                    }
                }
                (MatchResult::NoMatch, _) => {}
            }
        }
        if indeterminate {
            (MatchResult::Indeterminate, error)
        } else {
            (MatchResult::NoMatch, None)
        }
    }

    fn evaluate_all_of(
        &self,
        all_of: &AllOf,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> (MatchResult, Option<XacmlError>) {
        let mut error = None;
        for matched in &all_of.matches {
            match self.evaluate_match(matched, context, variables) {
                Ok(MatchResult::NoMatch) => {
                    return (MatchResult::NoMatch, None)
                }
                Ok(_) => {}
                Err(e) => {
                    if error.is_none() {
                        error = Some(e);
                    }
                }
            }
        }
        match error {
            Some(e) => (MatchResult::Indeterminate, Some(e)),
            None => (MatchResult::Match, None),
        }
    }

    // -----------------------------------------------------------------------
    // Rules (section 7.11).
    // -----------------------------------------------------------------------
    fn evaluate_rule(
        &self,
        rule: &Rule,
        context: &Context<'_>,
        variables: &Variables<'_>,
    ) -> NodeResult {
        let failed = rule.effect.indeterminate();
        match self.evaluate_target(
            rule.target.as_ref(),
            context,
            Some(variables),
        ) {
            (MatchResult::NoMatch, _) => {
                return NodeResult::of(Decision::NotApplicable);
            }
            // Defect 3 in the header: easy to write as NotApplicable, and it
            // hides a possible Deny when it is.
            (MatchResult::Indeterminate, error) => {
                return NodeResult::with_status(failed, error.as_ref());
            }
            (MatchResult::Match, _) => {}
        }
        let Some(condition) = &rule.condition else {
            return self.fired_rule(rule, context, variables);
        };
        let result =
            match self.evaluate_expression(condition, context, Some(variables))
            {
                Ok(result) => result,
                Err(error) => {
                    return NodeResult::with_status(failed, Some(&error));
                }
            };
        if result.values.len() != 1
            || canonical_type(&result.type_uri) != types::BOOLEAN
        {
            let error = XacmlError::processing(
                "A <Condition> must evaluate to exactly one boolean.",
            );
            return NodeResult::with_status(failed, Some(&error));
        }
        if result.values[0] == Value::Boolean(true) {
            self.fired_rule(rule, context, variables)
        } else {
            NodeResult::of(Decision::NotApplicable)
        }
    }

    /// A rule that fired, with its own obligations resolved HERE — the only
    /// place the rule's variables are still in scope. An assignment that is
    /// Indeterminate makes the RULE Indeterminate (section 7.18): a Permit
    /// with half its obligations is a PEP enforcing half the policy.
    fn fired_rule(
        &self,
        rule: &Rule,
        context: &Context<'_>,
        variables: &Variables<'_>,
    ) -> NodeResult {
        let decision = rule.effect.decision();
        let resolved = self
            .collect(&rule.obligations, decision, context, Some(variables))
            .and_then(|obligations| {
                self.collect(&rule.advice, decision, context, Some(variables))
                    .map(|advice| (obligations, advice))
            });
        match resolved {
            Ok((obligations, advice)) => NodeResult {
                decision,
                status: None,
                obligations,
                advice,
            },
            Err(error) => NodeResult::with_status(
                rule.effect.indeterminate(),
                Some(&error),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Policies and policy sets (sections 7.12 and 7.13).
    // -----------------------------------------------------------------------
    fn evaluate_policy(
        &self,
        policy: &Policy,
        context: &Context<'_>,
    ) -> XacmlResult<NodeResult> {
        let variables = Variables::new(&policy.variables);
        let Some(combiner) = self.combiners.get(&policy.combining_alg_id)
        else {
            return Ok(NodeResult::syntax(
                Decision::IndeterminateDP,
                format!(
                    "Unknown rule-combining algorithm \"{}\".",
                    policy.combining_alg_id
                ),
            ));
        };
        match self.evaluate_target(
            policy.target.as_ref(),
            context,
            Some(&variables),
        ) {
            (MatchResult::NoMatch, _) => {
                return Ok(NodeResult::of(Decision::NotApplicable));
            }
            (MatchResult::Indeterminate, error) => {
                return Ok(NodeResult::with_status(
                    Decision::IndeterminateDP,
                    error.as_ref(),
                ));
            }
            (MatchResult::Match, _) => {}
        }
        let combination = combiner.combine(policy.rules.len(), &mut |i| {
            Ok(self.evaluate_rule(&policy.rules[i], context, &variables))
        })?;
        let result = self.attach_obligations(
            combination,
            &policy.obligations,
            &policy.advice,
            context,
            Some(&variables),
        )?;
        if result.decision != Decision::NotApplicable {
            context.applicable.borrow_mut().push(PolicyIdentifier {
                is_policy_set: false,
                id: policy.id.clone(),
                version: policy.version.clone(),
            });
        }
        Ok(result)
    }

    fn evaluate_policy_set(
        &self,
        set: &PolicySet,
        context: &Context<'_>,
    ) -> XacmlResult<NodeResult> {
        match self.evaluate_target(set.target.as_ref(), context, None) {
            (MatchResult::NoMatch, _) => {
                return Ok(NodeResult::of(Decision::NotApplicable));
            }
            (MatchResult::Indeterminate, error) => {
                return Ok(NodeResult::with_status(
                    Decision::IndeterminateDP,
                    error.as_ref(),
                ));
            }
            (MatchResult::Match, _) => {}
        }
        let children: Vec<Child<'_>> = set
            .children
            .iter()
            .map(|child| resolve_child(child, context.repository))
            .collect();
        let mut evaluate = |i: usize| -> XacmlResult<NodeResult> {
            match children[i] {
                Child::Node(node) => self.evaluate_node(node, context),
                Child::Unresolved => Ok(NodeResult::syntax(
                    Decision::IndeterminateDP,
                    "Cannot evaluate an unresolved policy reference."
                        .to_string(),
                )),
            }
        };
        // only-one-applicable produces a combination of the SAME shape, so
        // it falls through to the same obligation handling: returning early
        // is what once dropped the set's own obligations (IIIA025, IIIA026).
        let combination = if set.combining_alg_id
            == policy_alg::ONLY_ONE_APPLICABLE
        {
            match self.only_one_applicable(&children, context, &mut evaluate)? {
                Ok(combination) => combination,
                Err(refusal) => return Ok(refusal),
            }
        } else if let Some(combiner) = self.combiners.get(&set.combining_alg_id)
        {
            combiner.combine(children.len(), &mut evaluate)?
        } else {
            return Ok(NodeResult::syntax(
                Decision::IndeterminateDP,
                format!(
                    "Unknown policy-combining algorithm \"{}\".",
                    set.combining_alg_id
                ),
            ));
        };
        let result = self.attach_obligations(
            combination,
            &set.obligations,
            &set.advice,
            context,
            None,
        )?;
        if result.decision != Decision::NotApplicable {
            context.applicable.borrow_mut().push(PolicyIdentifier {
                is_policy_set: true,
                id: set.id.clone(),
                version: set.version.clone(),
            });
        }
        Ok(result)
    }

    /// only-one-applicable (C.9): which children are APPLICABLE is decided
    /// before any is evaluated, because "more than one applies" is itself
    /// the error, and finding it out by evaluating would already have run
    /// policies it says should not both have run. The inner `Err` is a
    /// finished Indeterminate result.
    fn only_one_applicable(
        &self,
        children: &[Child<'_>],
        context: &Context<'_>,
        evaluate: &mut dyn FnMut(usize) -> XacmlResult<NodeResult>,
    ) -> XacmlResult<Result<Combination, NodeResult>> {
        let mut selected = None;
        for (i, child) in children.iter().enumerate() {
            match self.evaluate_target(child.target(), context, None) {
                (MatchResult::Indeterminate, error) => {
                    return Ok(Err(NodeResult::with_status(
                        Decision::IndeterminateDP,
                        error.as_ref(),
                    )));
                }
                (MatchResult::Match, _) => {
                    if selected.is_some() {
                        let error = XacmlError::processing(
                            "More than one policy in an only-one-applicable \
                             set is applicable.",
                        );
                        return Ok(Err(NodeResult::with_status(
                            Decision::IndeterminateDP,
                            Some(&error),
                        )));
                    }
                    selected = Some(i);
                }
                (MatchResult::NoMatch, _) => {}
            }
        }
        let Some(index) = selected else {
            return Ok(Ok(Combination {
                decision: Decision::NotApplicable,
                results: Vec::new(),
            }));
        };
        let result = evaluate(index)?;
        Ok(Ok(Combination {
            decision: result.decision,
            results: vec![result],
        }))
    }

    /// Section 7.18: nothing is collected unless the decision is Permit or
    /// Deny; children's first (inner-to-outer, the order they were decided
    /// in), then the node's own whose FulfillOn / AppliesTo matches.
    fn attach_obligations(
        &self,
        combination: Combination,
        obligations: &[ExpressionHolder],
        advice: &[ExpressionHolder],
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> XacmlResult<NodeResult> {
        let decision = combination.decision;
        let status = combination.results.iter().find_map(|r| r.status.clone());
        let mut result = NodeResult {
            status,
            ..NodeResult::of(decision)
        };
        if decision != Decision::Permit && decision != Decision::Deny {
            return Ok(result);
        }
        for child in combination.results {
            if child.decision == decision {
                result.obligations.extend(child.obligations);
                result.advice.extend(child.advice);
            }
        }
        result.obligations.extend(self.collect(
            obligations,
            decision,
            context,
            variables,
        )?);
        result
            .advice
            .extend(self.collect(advice, decision, context, variables)?);
        Ok(result)
    }

    fn collect(
        &self,
        holders: &[ExpressionHolder],
        decision: Decision,
        context: &Context<'_>,
        variables: Option<&Variables<'_>>,
    ) -> XacmlResult<Vec<ResolvedObligation>> {
        let mut resolved = Vec::new();
        for holder in holders {
            let fires = Effect::parse(&holder.on).map(Effect::decision);
            if fires != Some(decision) {
                continue;
            }
            let mut assignments = Vec::new();
            for assignment in &holder.assignments {
                let bag = self.evaluate_expression(
                    &assignment.expression,
                    context,
                    variables,
                )?;
                for value in bag.values {
                    assignments.push(ResolvedAssignment {
                        attribute_id: assignment.attribute_id.clone(),
                        category: assignment.category.clone(),
                        issuer: assignment.issuer.clone(),
                        type_uri: bag.type_uri.clone(),
                        lexical: self.datatypes.write(&bag.type_uri, &value)?,
                        value,
                    });
                }
            }
            resolved.push(ResolvedObligation {
                id: holder.id.clone(),
                assignments,
            });
        }
        Ok(resolved)
    }
}

/// A reference that cannot be found is Indeterminate rather than skipped: a
/// set that ignored it would evaluate a SUBSET of what somebody wrote.
fn resolve_child<'a>(
    child: &'a PolicyNode,
    repository: Option<&'a Repository>,
) -> Child<'a> {
    match child {
        PolicyNode::PolicyIdReference { reference, .. }
        | PolicyNode::PolicySetIdReference { reference, .. } => {
            match repository.and_then(|r| r.get(reference)) {
                Some(found) => Child::Node(found),
                None => Child::Unresolved,
            }
        }
        node => Child::Node(node),
    }
}

/// The three attributes the PDP supplies itself (section 10.2.5), in UTC
/// and to the whole second. `None` for anything else, which is what keeps
/// this from becoming a fallback that invents values.
fn environment_attribute(
    designator: &Designator,
    now: SystemTime,
) -> Option<Value> {
    if designator.category != category::ENVIRONMENT {
        return None;
    }
    let seconds = match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    };
    let days = seconds.div_euclid(86400);
    let of_day = seconds.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) =
        (of_day / 3600, of_day % 3600 / 60, of_day % 60);
    let instant = |shape| Temporal {
        shape,
        year,
        month,
        day,
        hour,
        minute,
        second: second as f64,
        tz: Some(0),
    };
    let id = designator.attribute_id.as_str();
    let ty = designator.data_type.as_str();
    if id == attribute::CURRENT_DATETIME && ty == types::DATETIME {
        return Some(Value::Temporal(instant(TemporalShape::DateTime)));
    }
    if id == attribute::CURRENT_DATE && ty == types::DATE {
        return Some(Value::Temporal(Temporal {
            hour: 0,
            minute: 0,
            second: 0.0,
            ..instant(TemporalShape::Date)
        }));
    }
    if id == attribute::CURRENT_TIME && ty == types::TIME {
        return Some(Value::Temporal(Temporal {
            year: 1970,
            month: 1,
            day: 1,
            ..instant(TemporalShape::Time)
        }));
    }
    None
}
