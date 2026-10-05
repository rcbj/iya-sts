// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ACCESS-CONTROL POLICY (`xacml_templates.ts`'s `access-control` and
//! `xacml_access_pep.ts`'s request and decision): what the embedded PEP asks
//! before a subject reaches the console, the management API, the User
//! Portal, SCIM or the SPIRE Server API.
//!
//! **ONE Permit rule whose condition CONJOINS two questions**, under
//! deny-unless-permit: does the subject satisfy the resource's ROLE
//! requirement (holding one it names, or it naming none), AND its OWNERSHIP
//! requirement (the resource naming no owner, or the subject being that
//! owner)? **They are conjoined and not alternatives, and the first draft in
//! Node got that wrong**: written as three OR'd arms, "the resource requires
//! nothing" was true for the portal, which narrows nobody, and swallowed the
//! owner comparison — any signed-in person reached any other person's
//! account. A helpdesk role that may manage somebody else's account is a
//! SECOND rule, not an edit to this one.
//!
//! The document is emitted as XACML 3.0 XML — the form a stored override
//! takes — and read by this crate's own reader, so one reader serves the
//! built-in document and an operator's.
//!
//! What the caller supplies: the roles the subject holds (the register's and
//! the computed built-ins), and the roles the resource requires (the
//! caller's, or the application register's). Both are registers the runtime
//! holds; the decision here is complete without them.

use crate::builder::{vocabulary, AuthorizationRequest};
use crate::model::{
    category, rule_alg, types, Decision, XacmlResult, NS_XACML,
};
use crate::pdp::{EvaluationOptions, Pdp};
use crate::policy::PolicyNode;
use crate::request::Request;

/// The policy's name where `xacml.accessPolicy` names none.
pub const DEFAULT_NAME: &str = "access-control";
/// On the SUBJECT: whether it authenticated.
pub const AUTHENTICATED: &str = "urn:sts:xacml:authenticated";
/// On the RESOURCE: who owns it (the portal's account).
pub const OWNER: &str = "urn:sts:xacml:resource-owner";
/// On the RESOURCE: the roles that may reach it.
pub const REQUIRED_ROLE: &str = "urn:sts:xacml:required-role";

const F1: &str = "urn:oasis:names:tc:xacml:1.0:function:";
const F3: &str = "urn:oasis:names:tc:xacml:3.0:function:";
const SUBJECT_ID: &str = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

/// The template's three parameters, each `yes` by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    /// The User Portal's rule — a CONSTRAINT: a resource naming an owner is
    /// reachable only by that owner. `false` refuses it to everybody.
    pub permit_owner: bool,
    /// A surface nobody has narrowed behaves as before there was a policy.
    pub permit_when_nothing_required: bool,
    /// An unauthenticated session is a subject; this keeps it out.
    pub require_authenticated: bool,
}

impl Default for Parameters {
    fn default() -> Parameters {
        Parameters {
            permit_owner: true,
            permit_when_nothing_required: true,
            require_authenticated: true,
        }
    }
}

fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn apply(function: &str, args: &[String]) -> String {
    format!(
        "<Apply FunctionId=\"{}\">{}</Apply>",
        function,
        args.concat()
    )
}

fn function(id: &str) -> String {
    format!("<Function FunctionId=\"{}\"/>", id)
}

fn designator(cat: &str, id: &str, data_type: &str) -> String {
    format!(
        "<AttributeDesignator Category=\"{}\" AttributeId=\"{}\" DataType=\"{}\" MustBePresent=\"false\"/>",
        cat, id, data_type
    )
}

fn value(data_type: &str, text: &str) -> String {
    format!(
        "<AttributeValue DataType=\"{}\">{}</AttributeValue>",
        data_type,
        esc(text)
    )
}

fn empty(cat: &str, id: &str) -> String {
    apply(
        &format!("{}integer-equal", F1),
        &[
            apply(
                &format!("{}string-bag-size", F1),
                &[designator(cat, id, types::STRING)],
            ),
            value(types::INTEGER, "0"),
        ],
    )
}

/// `buildAccessControl()`, as XACML 3.0 XML under the policy id `name`.
pub fn document(name: &str, p: Parameters) -> String {
    let string_equal = function(&format!("{}string-equal", F1));
    let holds_required_role = apply(
        &format!("{}any-of-any", F3),
        &[
            string_equal.clone(),
            designator(
                category::ACCESS_SUBJECT,
                vocabulary::ROLE,
                types::STRING,
            ),
            designator(category::RESOURCE, REQUIRED_ROLE, types::STRING),
        ],
    );
    let mut role_arms = vec![holds_required_role];
    if p.permit_when_nothing_required {
        role_arms.push(empty(category::RESOURCE, REQUIRED_ROLE));
    }
    let satisfies_role = if role_arms.len() == 1 {
        role_arms.remove(0)
    } else {
        apply(&format!("{}or", F1), &role_arms)
    };
    let ownerless = empty(category::RESOURCE, OWNER);
    let is_the_owner = apply(
        &format!("{}any-of-any", F3),
        &[
            string_equal,
            designator(category::ACCESS_SUBJECT, SUBJECT_ID, types::STRING),
            designator(category::RESOURCE, OWNER, types::STRING),
        ],
    );
    let satisfies_ownership = if p.permit_owner {
        apply(&format!("{}or", F1), &[ownerless, is_the_owner])
    } else {
        ownerless
    };
    let mut conjuncts = Vec::new();
    if p.require_authenticated {
        // `any-of` is a 3.0 function: written under 1.0's namespace it is a
        // function nothing implements, Indeterminate, and so a Deny of
        // everybody that says only "the policy denied it".
        conjuncts.push(apply(
            &format!("{}any-of", F3),
            &[
                function(&format!("{}boolean-equal", F1)),
                value(types::BOOLEAN, "true"),
                designator(
                    category::ACCESS_SUBJECT,
                    AUTHENTICATED,
                    types::BOOLEAN,
                ),
            ],
        ));
    }
    conjuncts.push(satisfies_role);
    conjuncts.push(satisfies_ownership);
    let condition = if conjuncts.len() == 1 {
        conjuncts.remove(0)
    } else {
        apply(&format!("{}and", F1), &conjuncts)
    };
    format!(
        "<Policy xmlns=\"{ns}\" PolicyId=\"{id}\" Version=\"1.0\" RuleCombiningAlgId=\"{alg}\">\
         <Description>The access-control policy: permit when the subject satisfies the resource's role \
         requirement AND its ownership requirement; everything else is denied.</Description>\
         <Target/>\
         <Rule RuleId=\"{id}:rule:may-reach-it\" Effect=\"Permit\">\
         <Description>Ownership is a constraint rather than a way round the roles.</Description>\
         <Condition>{condition}</Condition></Rule></Policy>",
        ns = NS_XACML,
        id = esc(name),
        alg = rule_alg::DENY_UNLESS_PERMIT,
        condition = condition
    )
}

/// The built-in document, read.
pub fn built_in(name: &str, p: Parameters) -> XacmlResult<PolicyNode> {
    crate::xml::parse_policy(&document(name, p))
}

/// What is asked: a resource, an action, the owner where the resource has
/// one, and the subject.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Question {
    pub resource: String,
    pub action: String,
    pub owner: Option<String>,
    /// Empty for an unauthenticated caller.
    pub subject: String,
    pub authenticated: bool,
}

/// `buildRequest()`: through the one builder, an empty value left out of
/// its bag, so an ownerless surface sends no owner rather than one called "".
pub fn request(q: &Question, held: &[String], required: &[String]) -> Request {
    let mut r = AuthorizationRequest::new(true, true, false);
    r.principal(&q.subject, None)
        .roles(held.iter().map(String::as_str).collect::<Vec<_>>())
        .subject(AUTHENTICATED, vec![q.authenticated])
        .target(&q.resource, None)
        .resource(
            REQUIRED_ROLE,
            required.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .resource(OWNER, vec![q.owner.clone().unwrap_or_default()])
        .requested_action(&q.action);
    r.category(category::ENVIRONMENT);
    r.build()
}

/// Why a refusal: the three mean different things to whoever has to fix one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Deny,
    /// A fault in the policy rather than a decision about the subject.
    Indeterminate,
    /// Not covered, and deny-unless-permit makes that a refusal.
    NotApplicable,
}

impl Refused {
    /// The operator's code.
    pub fn code(self) -> &'static str {
        match self {
            Refused::Deny => "STS-XACML-0044",
            Refused::Indeterminate => "STS-XACML-0045",
            Refused::NotApplicable => "STS-XACML-0046",
        }
    }
}

/// The answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub allowed: bool,
    pub decision: Decision,
    pub refused: Option<Refused>,
    pub why: String,
}

/// `decide()`'s evaluation and wording, for a policy already loaded.
/// `held` is what the subject holds, the caller's own roles included;
/// `required` what the resource requires.
pub fn decide(
    policy: &PolicyNode,
    q: &Question,
    held: &[String],
    required: &[String],
) -> Answer {
    let response = Pdp::new().evaluate(
        policy,
        &request(q, held, required),
        &EvaluationOptions::default(),
    );
    if response.decision == Decision::Permit {
        return Answer {
            allowed: true,
            decision: response.decision,
            refused: None,
            why: "The access policy permitted it.".into(),
        };
    }
    let who = if q.subject.is_empty() {
        "an unauthenticated caller".to_string()
    } else {
        format!(
            "\"{}\"{}",
            q.subject,
            if q.authenticated {
                ""
            } else {
                " (who did not authenticate)"
            }
        )
    };
    let what = format!(
        "{} on {}{}",
        q.action,
        q.resource,
        q.owner
            .as_ref()
            .map(|o| format!(", owned by \"{}\"", o))
            .unwrap_or_default()
    );
    let (refused, why) = match response.decision {
        Decision::Deny => (
            Refused::Deny,
            format!(
                "The access policy denied {} for {}. They hold {}; it requires {}.",
                what,
                who,
                if held.is_empty() { "no role".to_string() } else { held.join(", ") },
                if required.is_empty() { "nothing".to_string() } else { required.join(" or ") }
            ),
        ),
        Decision::NotApplicable => (
            Refused::NotApplicable,
            format!(
                "The access policy did not cover {}, and its combining algorithm is deny-unless-permit — so a \
                 question it does not answer is a refusal rather than a permission.",
                what
            ),
        ),
        _ => (
            Refused::Indeterminate,
            format!(
                "The access policy could not be evaluated for {} ({}), which is a fault in the policy rather \
                 than a decision about {}.",
                what,
                response.status.message.clone().unwrap_or_else(|| "no reason given".into()),
                who
            ),
        ),
    };
    Answer {
        allowed: false,
        decision: response.decision,
        refused: Some(refused),
        why,
    }
}
