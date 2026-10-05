// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The PIP this container does not have, fetched from the one that does. A
//! port of `xacml-pep/pip.js`.
//!
//! **The engine's resolver is synchronous**, and an HTTP request is not. So
//! the fetch happens BEFORE evaluation: the policy is walked for every
//! access-subject designator it could ask about, all of them are fetched in
//! ONE `POST /xacml/pip`, and the evaluation gets a resolver over what came
//! back. That is why the PDP's endpoint takes a list.
//!
//! **The walk is static and deliberately over-fetches** — targets,
//! conditions, variables, obligation and advice assignments, a policy set's
//! children and what a `PolicyIdReference` names in the held repository. A
//! static walk cannot decide anything; evaluating twice could.
//!
//! **A missed designator is an empty bag and never an error.** Every
//! failure is a resolver answering empty bags — which is what this
//! container did before it had a PIP — reported on `GET /`.

use std::collections::{HashMap, HashSet};
use sts_core::errors::codes;

use indexmap::IndexMap;
use reqwest::Method;
use serde_json::{json, Value};
use sts_core::log::tag;
use sts_xacml::builder::vocabulary;
use sts_xacml::datatypes::DataTypes;
use sts_xacml::model::{attribute, canonical_type, category, types, NS_XACML};
use sts_xacml::pdp::{AttributeResolver, Repository};
use sts_xacml::policy::{
    Designator, Expression, ExpressionHolder, PolicyNode, Target,
};
use sts_xacml::request::Request;
use sts_xacml::value::Value as XacmlValue;
use sts_xacml::xml;

use crate::pdp_client::{Body, PdpClient};

/// The namespace of the two elements XACML does not define.
const PIP_NS: &str = "urn:sts:xacml:pip:1.0";

/// The PDP refuses more than fifty designators in one query, so this refuses
/// to send more — the message then names the policy, not the request.
pub const MAX_DESIGNATORS: usize = 50;

/// Category, AttributeId and DataType: what makes two designators different
/// questions to the PIP.
type Key = (String, String, String);

fn key_of(d: &Designator) -> Key {
    (
        d.category.clone(),
        d.attribute_id.clone(),
        d.data_type.clone(),
    )
}

// ---------------------------------------------------------------------------
// THE WALK.
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Walk {
    found: IndexMap<Key, Designator>,
    seen: HashSet<String>,
}

impl Walk {
    fn expression(&mut self, expression: &Expression) {
        match expression {
            // Only access-subject: the only category the PDP's PIP resolves.
            Expression::Designator(d) => {
                if d.category == category::ACCESS_SUBJECT {
                    self.found.entry(key_of(d)).or_insert_with(|| d.clone());
                }
            }
            Expression::Apply(apply) => {
                for arg in &apply.args {
                    self.expression(arg);
                }
            }
            // A variableRef's DEFINITION is walked where the definitions are.
            _ => {}
        }
    }

    fn target(&mut self, target: Option<&Target>) {
        for any_of in target.iter().flat_map(|t| &t.any_of) {
            for all_of in &any_of.all_of {
                for matched in &all_of.matches {
                    self.expression(&matched.reference);
                    self.expression(&matched.value);
                }
            }
        }
    }

    fn holders(&mut self, holders: &[ExpressionHolder]) {
        for holder in holders {
            for assignment in &holder.assignments {
                self.expression(&assignment.expression);
            }
        }
    }

    fn node(&mut self, node: &PolicyNode, repository: &Repository) {
        match node {
            PolicyNode::PolicyIdReference { reference, .. }
            | PolicyNode::PolicySetIdReference { reference, .. } => {
                // A reference to something absent is SKIPPED: the evaluator
                // meets it too and reports it better than this could.
                if let Some(found) = repository.get(reference) {
                    self.node(found, repository);
                }
            }
            PolicyNode::Policy(policy) => {
                // A cycle through references would be an infinite walk.
                if !policy.id.is_empty() && !self.seen.insert(policy.id.clone())
                {
                    return;
                }
                self.target(policy.target.as_ref());
                self.holders(&policy.obligations);
                self.holders(&policy.advice);
                for definition in policy.variables.values() {
                    self.expression(definition);
                }
                for rule in &policy.rules {
                    self.target(rule.target.as_ref());
                    if let Some(condition) = &rule.condition {
                        self.expression(condition);
                    }
                    self.holders(&rule.obligations);
                    self.holders(&rule.advice);
                }
            }
            PolicyNode::PolicySet(set) => {
                if !set.id.is_empty() && !self.seen.insert(set.id.clone()) {
                    return;
                }
                self.target(set.target.as_ref());
                self.holders(&set.obligations);
                self.holders(&set.advice);
                for child in &set.children {
                    self.node(child, repository);
                }
            }
        }
    }
}

/// Every access-subject designator reachable in a policy, in the order met.
pub fn designators_in(
    root: &PolicyNode,
    repository: &Repository,
) -> Vec<Designator> {
    let mut walk = Walk::default();
    walk.node(root, repository);
    walk.found.into_values().collect()
}

// ---------------------------------------------------------------------------
// THE QUERY.
// ---------------------------------------------------------------------------
fn first_subject_value(
    request: &Request,
    attribute_id: &str,
) -> Option<String> {
    request
        .categories
        .iter()
        .filter(|c| c.category == category::ACCESS_SUBJECT)
        .flat_map(|c| &c.attributes)
        .find(|a| a.attribute_id == attribute_id && !a.values.is_empty())
        .map(|a| a.values[0].lexical.clone())
}

/// The request's subject-id, or `""`.
pub fn subject_id_of(request: &Request) -> String {
    first_subject_value(request, attribute::SUBJECT_ID).unwrap_or_default()
}

/// `application` when the request says the subject is one (#303).
pub fn subject_kind_of(request: &Request) -> &'static str {
    let is_application = request
        .categories
        .iter()
        .filter(|c| c.category == category::ACCESS_SUBJECT)
        .flat_map(|c| &c.attributes)
        .any(|a| {
            a.attribute_id == vocabulary::SUBJECT_KIND
                && a.values.first().map(|v| v.lexical.as_str())
                    == Some("application")
        });
    if is_application {
        "application"
    } else {
        "user"
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The query document: the access-subject of the request being decided,
/// written back out, and the designators.
pub fn query_document(
    subject: &str,
    designators: &[Designator],
    kind: &str,
) -> String {
    let mut parts = vec![
        r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string(),
        format!(r#"<PIPRequest xmlns="{}">"#, PIP_NS),
        format!(
            r#"  <Request xmlns="{}" CombinedDecision="false" ReturnPolicyIdList="false">"#,
            NS_XACML
        ),
        format!(
            r#"    <Attributes Category="{}">"#,
            category::ACCESS_SUBJECT
        ),
        format!(
            r#"      <Attribute AttributeId="{}" IncludeInResult="true">"#,
            attribute::SUBJECT_ID
        ),
        format!(
            r#"        <AttributeValue DataType="{}">{}</AttributeValue>"#,
            types::STRING,
            escape(subject)
        ),
        "      </Attribute>".to_string(),
    ];
    if kind == "application" {
        parts.push(format!(
            r#"      <Attribute AttributeId="{}" IncludeInResult="false">"#,
            vocabulary::SUBJECT_KIND
        ));
        parts.push(format!(r#"        <AttributeValue DataType="{}">application</AttributeValue>"#, types::STRING));
        parts.push("      </Attribute>".to_string());
    }
    parts.push("    </Attributes>".to_string());
    parts.push("  </Request>".to_string());
    for d in designators {
        parts.push(format!(
            r#"  <AttributeDesignator xmlns="{}" Category="{}" AttributeId="{}" DataType="{}" MustBePresent="false"/>"#,
            NS_XACML, escape(&d.category), escape(&d.attribute_id),
            escape(&d.data_type)
        ));
    }
    parts.push("</PIPRequest>".to_string());
    parts.join("\n") + "\n"
}

/// What the PDP answered: lexical values by designator key, and the
/// designators it could not resolve, with why.
#[derive(Debug, Default)]
pub struct PipAnswer {
    pub answers: HashMap<Key, Vec<String>>,
    pub unresolved: Vec<(String, String)>,
}

/// Reads a `<PIPResponse>` with the engine's own request reader: the
/// `<Attributes>` are a request fragment, so nothing here parses a value by
/// hand.
pub fn read_answer(text: &str) -> Result<PipAnswer, String> {
    let document = roxmltree::Document::parse(text)
        .map_err(|e| format!("not well-formed XML: {}", e))?;
    let root = document.root_element();
    if root.tag_name().name() != "PIPResponse" {
        return Err(format!(
            "the PDP answered <{}> where a <PIPResponse> was \
                            expected",
            root.tag_name().name()
        ));
    }
    let request = xml::read_request(root).map_err(|e| e.message)?;
    let mut answer = PipAnswer::default();
    for cat in &request.categories {
        for attr in &cat.attributes {
            for value in &attr.values {
                answer
                    .answers
                    .entry((
                        cat.category.clone(),
                        attr.attribute_id.clone(),
                        canonical_type(&value.type_uri).to_string(),
                    ))
                    .or_default()
                    .push(value.lexical.clone());
            }
        }
    }
    if let Some(container) = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Unresolved")
    {
        for node in container
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "Designator")
        {
            let why = node
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "Reason")
                .map(|r| {
                    r.descendants()
                        .filter(|t| t.is_text())
                        .filter_map(|t| t.text())
                        .collect()
                })
                .unwrap_or_default();
            answer.unresolved.push((
                node.attribute("AttributeId").unwrap_or("").to_string(),
                why,
            ));
        }
    }
    Ok(answer)
}

/// A resolver over what the PDP answered: PARSED values at the designator's
/// declared type. A value that will not parse at that type is dropped with a
/// warning — reaching that means the PDP wrote a form it cannot read back.
pub struct RemoteResolver {
    answer: PipAnswer,
}

impl AttributeResolver for RemoteResolver {
    fn resolve(&self, designator: &Designator) -> Vec<XacmlValue> {
        let Some(lexicals) = self.answer.answers.get(&key_of(designator))
        else {
            return Vec::new();
        };
        lexicals
            .iter()
            .filter_map(|lexical| {
                match DataTypes::standard()
                    .parse(&designator.data_type, lexical)
                {
                    Ok(value) => Some(value),
                    Err(error) => {
                        tracing::warn!(
                            "{}pip: the PDP answered \"{}\" for {}, which is \
                             not a valid {}: {}",
                            tag(codes::STS_XPEP_0028),
                            lexical,
                            designator.attribute_id,
                            designator.data_type,
                            error
                        );
                        None
                    }
                }
            })
            .collect()
    }
}

/// The resolver for one decision, and the report `GET /` and the answer
/// carry. **It never fails**: every failure is no resolver and a `why`.
pub struct Resolution {
    pub resolver: Option<RemoteResolver>,
    pub report: Value,
}

/// The remote PIP, as `pep.js` calls it before each evaluation.
pub struct RemotePip {
    client: PdpClient,
    enabled: bool,
}

impl RemotePip {
    pub fn new(client: PdpClient, enabled: bool) -> RemotePip {
        RemotePip { client, enabled }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn resolver_for(
        &self,
        request: &Request,
        root: &PolicyNode,
        repository: &Repository,
    ) -> Resolution {
        let none = |report: Value| Resolution {
            resolver: None,
            report,
        };
        if !self.enabled {
            return none(json!({ "used": false,
                "why": "PEP_PIP is off, so this PEP decides on what the \
                        request asserts and nothing else — which is what a \
                        remote PEP with no Policy Information Point does." }));
        }
        let subject = subject_id_of(request);
        if subject.is_empty() {
            return none(json!({ "used": false,
                "why": "the request names no subject-id, so there is no \
                        directory entry to resolve anything against." }));
        }
        let designators = designators_in(root, repository);
        if designators.is_empty() {
            return none(json!({ "used": false, "subject": subject,
                "why": "the policy this PEP holds designates no \
                        access-subject attribute, so there is nothing to ask \
                        the PIP for." }));
        }
        let count = designators.len();
        if count > MAX_DESIGNATORS {
            tracing::warn!(
                "{}pip: the policy designates {} access-subject attributes \
                 and the PDP accepts at most {} per query, so NONE was \
                 fetched and every designator will resolve to an empty bag. \
                 Split the policy, or turn PEP_PIP off and assert the \
                 attributes in the request.",
                tag(codes::STS_XPEP_0024),
                count,
                MAX_DESIGNATORS
            );
            return none(json!({ "used": false, "subject": subject,
                "designators": count,
                "why": format!("the policy designates {} access-subject \
                                attributes, which is more than the PDP will \
                                answer in one query ({}).",
                               count, MAX_DESIGNATORS) }));
        }
        let document =
            query_document(&subject, &designators, subject_kind_of(request));
        let answered = self
            .client
            .call(Method::POST, "/xacml/pip", Some(Body::Xml(document)))
            .await;
        if answered.error.is_some() || answered.status != 200 {
            let why = match &answered.error {
                Some(error) => {
                    format!("the PIP query could not be made: {}", error)
                }
                None => format!(
                    "the PDP answered {} to the PIP query{}.",
                    answered.status,
                    if answered.status == 403 {
                        " — POST /xacml/pip requires a client certificate \
                         this service VERIFIES whose subject holds the \
                         built-in REMOTE_PEPS role, so check PEP_TLS_CERT and \
                         the group roles.remotePepGroup names"
                    } else {
                        ""
                    }
                ),
            };
            tracing::warn!(
                "{}pip: {} Every designator will resolve to an empty bag, \
                 which is what this PEP did before it had a PIP at all — so \
                 it goes on deciding, on less information, and says so.",
                tag(if answered.error.is_some() {
                    codes::STS_XPEP_0025
                } else {
                    codes::STS_XPEP_0026
                }),
                why
            );
            return none(json!({ "used": false, "subject": subject,
                "designators": count, "failed": true, "why": why }));
        }
        let read = match read_answer(&answered.text) {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    "{}pip: the PDP's answer would not parse ({}), so every \
                     designator resolves to an empty bag.",
                    tag(codes::STS_XPEP_0027),
                    error
                );
                return none(json!({ "used": false, "subject": subject,
                    "designators": count, "failed": true,
                    "why": format!("the PDP's answer would not parse: {}",
                                   error) }));
            }
        };
        let resolved = read.answers.len();
        tracing::info!(
            "pip: resolved {} of {} designator(s) about \"{}\" against the \
             PDP's embedded directory.",
            resolved,
            count,
            subject
        );
        let unresolved: Vec<Value> = read
            .unresolved
            .iter()
            .map(|(id, why)| json!({ "attributeId": id, "why": why }))
            .collect();
        Resolution {
            resolver: Some(RemoteResolver { answer: read }),
            report: json!({ "used": true, "subject": subject,
                "designators": count, "resolved": resolved,
                "unresolved": unresolved }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str =
        "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";

    fn designator(id: &str) -> String {
        format!(
            r#"<AttributeDesignator Category="{}" AttributeId="{}" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/>"#,
            S, id
        )
    }

    /// The five places a designator can hide, as `tests/xacml_pep.js` drives
    /// `pip.js`'s walk: a target, a condition, a variable definition, an
    /// obligation assignment and a policy reached by reference — and one in a
    /// resource category, which must NOT be asked for.
    #[test]
    fn the_walk_finds_a_designator_in_five_places() {
        let eq = "urn:oasis:names:tc:xacml:1.0:function:string-equal";
        let bag = "urn:oasis:names:tc:xacml:1.0:function:string-bag-size";
        let gt = "urn:oasis:names:tc:xacml:1.0:function:integer-greater-than";
        let referenced = format!(
            r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="inner" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"><Target><AnyOf><AllOf><Match MatchId="{eq}"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">x</AttributeValue>{}</Match></AllOf></AnyOf></Target><Rule RuleId="r" Effect="Permit"/></Policy>"#,
            designator("inReference")
        );
        let root = format!(
            r#"<PolicySet xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicySetId="root" Version="1.0" PolicyCombiningAlgId="urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable"><Target/>
<Policy PolicyId="p" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable">
<Target><AnyOf><AllOf><Match MatchId="{eq}"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">x</AttributeValue>{t}</Match></AllOf></AnyOf></Target>
<VariableDefinition VariableId="v"><Apply FunctionId="{bag}">{v}</Apply></VariableDefinition>
<Rule RuleId="r" Effect="Permit"><Condition><Apply FunctionId="{gt}"><Apply FunctionId="{bag}">{c}</Apply><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">0</AttributeValue></Apply></Condition>
<ObligationExpressions><ObligationExpression ObligationId="o" FulfillOn="Permit"><AttributeAssignmentExpression AttributeId="a">{o}</AttributeAssignmentExpression></ObligationExpression></ObligationExpressions></Rule>
<Rule RuleId="r2" Effect="Deny"><Condition><Apply FunctionId="{gt}"><Apply FunctionId="{bag}"><AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource" AttributeId="inResource" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/></Apply><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">0</AttributeValue></Apply></Condition></Rule>
</Policy><PolicyIdReference>inner</PolicyIdReference></PolicySet>"#,
            t = designator("inTarget"),
            v = designator("inVariable"),
            c = designator("inCondition"),
            o = designator("inObligation")
        );
        let root = xml::parse_policy(&root).unwrap();
        let mut repository = Repository::new();
        repository
            .insert("inner".into(), xml::parse_policy(&referenced).unwrap());
        let ids: Vec<String> = designators_in(&root, &repository)
            .into_iter()
            .map(|d| d.attribute_id)
            .collect();
        for wanted in [
            "inTarget",
            "inVariable",
            "inCondition",
            "inObligation",
            "inReference",
        ] {
            assert!(
                ids.contains(&wanted.to_string()),
                "{} in {:?}",
                wanted,
                ids
            );
        }
        assert!(!ids.contains(&"inResource".to_string()));
        let query = query_document(
            "alice",
            &designators_in(&root, &repository),
            "user",
        );
        assert!(query.contains("<PIPRequest") && query.contains("alice"));
    }

    #[test]
    fn reads_an_answer_with_the_engine_reader() {
        let text = format!(
            r#"<PIPResponse xmlns="urn:sts:xacml:pip:1.0">
  <Attributes xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" Category="{S}">
    <Attribute AttributeId="employeeType" IncludeInResult="false">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">staff</AttributeValue>
    </Attribute>
  </Attributes>
  <Unresolved><Designator AttributeId="title"><Reason>not on the entry</Reason></Designator></Unresolved>
</PIPResponse>"#
        );
        let read = read_answer(&text).unwrap();
        let key = (
            S.to_string(),
            "employeeType".to_string(),
            types::STRING.to_string(),
        );
        assert_eq!(read.answers.get(&key), Some(&vec!["staff".to_string()]));
        assert_eq!(
            read.unresolved,
            vec![("title".to_string(), "not on the entry".to_string())]
        );
    }
}
