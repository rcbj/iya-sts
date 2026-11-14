// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ACCESS-CONTROL POLICY (`xacml_templates.ts`'s `access-control` and
//! `xacml_access_pep.ts`'s request and decision): what the embedded PEP asks
//! before a subject reaches the console, the management API, the User
//! Portal, the report API, SCIM or the SPIRE Server API.
//!
//! **FOUR PERMIT RULES under deny-unless-permit**, each a sentence of its
//! own, because under deny-unless-permit a new kind of access is a new rule
//! and the rules before it are untouched:
//!
//! 1. `may-reach-it`: ONE condition CONJOINING the subject's
//!    authentication, the resource's ROLE requirement (holding one it
//!    names, or it naming none), EVERY role it names as required-all
//!    (#454), and its OWNERSHIP requirement (the resource naming no owner,
//!    or the subject being that owner) — and never an AuthZEN access
//!    request, which only rule 4 decides. **They are conjoined and not
//!    alternatives, and the first draft in Node got that wrong**: written as
//!    three OR'd arms, "the resource requires nothing" was true for the
//!    portal, which narrows nobody, and swallowed the owner comparison — any
//!    signed-in person reached any other person's account.
//! 2. `owner-administers-what-they-own` (#607): an OWNER holding OWNER_READ
//!    or OWNER_WRITE administers, through the management API, what they own,
//!    within the actions listed for its kind, never what is closed to its
//!    owners and never taking the last owner off.
//! 3. `report-administrators-and-shares` (#1030): a PERSON holding
//!    REPORT_ADMIN reaches any report row; one holding a report role the
//!    listed actions on a row shared with a group of theirs.
//! 4. `access-request-approvers` (#1180): who may approve, deny or revoke an
//!    AuthZEN access request — the approvers its advice named, or an Admin
//!    Write administrator through the management API, and never its subject
//!    or its requester.
//!
//! The document is emitted as XACML 3.0 XML — the form a stored override
//! takes — and read by this crate's own reader, so one reader serves the
//! built-in document and an operator's; read and written again it is byte
//! for byte the document Node writes (`tests/node_vectors.rs`).
//!
//! What the caller supplies: the roles the subject holds (the register's and
//! the computed built-ins), and the roles the resource requires (the
//! caller's, or the application register's). Both are registers the runtime
//! holds; the decision here is complete without them. The facts the PIP
//! reads out of the directory — an object's owners, whether it is closed to
//! them, who the person is as an owner — come through
//! [`EvaluationOptions::resolver`], as Node's come through its PIP.

use std::collections::BTreeMap;

use crate::builder::{vocabulary, AuthorizationRequest};
use crate::model::{
    attribute, category, rule_alg, types, Decision, XacmlResult, NS_XACML,
};
use crate::pdp::{EvaluationOptions, Pdp};
use crate::policy::PolicyNode;
use crate::request::Request;

/// The policy's name where `xacml.accessPolicy` names none.
pub const DEFAULT_NAME: &str = "access-control";

// `ISSUANCE_ATTRIBUTE`'s identifiers the access-control document and its
// request use, spelt as `xacml_templates.ts` spells them.
/// On the SUBJECT: whether it authenticated.
pub const AUTHENTICATED: &str = "urn:sts:xacml:authenticated";
/// On the RESOURCE: who owns it (the portal's account, a report row).
pub const OWNER: &str = "urn:sts:xacml:resource-owner";
/// On the RESOURCE: the roles that may reach it, any one of them.
pub const REQUIRED_ROLE: &str = "urn:sts:xacml:required-role";
/// On the RESOURCE: roles the subject must hold EVERY one of (#454).
pub const REQUIRED_ALL_ROLE: &str = "urn:sts:xacml:required-all-role";
/// The owner rule's (#607).
pub const OWNER_REQUIRED_ROLE: &str = "urn:sts:xacml:owner-required-role";
pub const OBJECT_KIND: &str = "urn:sts:xacml:object-kind";
pub const OBJECT_ID: &str = "urn:sts:xacml:object-id";
pub const OBJECT_OWNER: &str = "urn:sts:xacml:object-owner";
pub const OBJECT_PROTECTED: &str = "urn:sts:xacml:object-protected";
pub const OBJECT_ATTRIBUTE: &str = "urn:sts:xacml:object-attribute";
pub const ADMIN_ACTION: &str = "urn:sts:xacml:admin-action";
pub const OWNER_SUBJECT: &str = "urn:sts:xacml:owner-subject";
pub const OWNER_IDENTITY: &str = "urn:sts:xacml:owner-identity";
/// The report rule's (#1030).
pub const REPORT_OBJECT_KIND: &str = "urn:sts:xacml:report-object-kind";
pub const REPORT_SHARED_GROUP: &str = "urn:sts:xacml:report-shared-group";
/// The access request rule's (#1180).
pub const ACCESS_REQUEST_ID: &str = "urn:sts:xacml:authzen:access-request-id";
pub const ACCESS_REQUEST_REQUESTER: &str =
    "urn:sts:xacml:authzen:request-requester";
pub const ACCESS_REQUEST_SUBJECT: &str =
    "urn:sts:xacml:authzen:request-subject";
pub const ACCESS_REQUEST_SUBJECT_TYPE: &str =
    "urn:sts:xacml:authzen:request-subject-type";
pub const ACCESS_REQUEST_ACTION: &str = "urn:sts:xacml:authzen:request-action";
pub const ACCESS_REQUEST_RESOURCE: &str =
    "urn:sts:xacml:authzen:request-resource";
pub const ACCESS_REQUEST_RESOURCE_TYPE: &str =
    "urn:sts:xacml:authzen:request-resource-type";
pub const ACCESS_REQUEST_APPLICATION: &str =
    "urn:sts:xacml:authzen:request-application";
pub const APPROVER_ELIGIBLE: &str = "urn:sts:xacml:authzen:approver-eligible";
pub const APPROVER_IDENTITY: &str = "urn:sts:xacml:authzen:approver-identity";
pub const APPROVER_DOOR: &str = "urn:sts:xacml:authzen:approver-door";

// `common/access_gate.ts`'s RESOURCE.REPORT_API, RESOURCE.AUTHZEN_ACCESS_
// REQUEST and ACTION.APPROVE_ACCESS_REQUEST, written out as the template
// writes them.
const REPORT_API: &str = "report-api";
const ACCESS_REQUEST: &str = "authzen-access-request";
const APPROVE_ACCESS_REQUEST: &str = "approve-access-request";

const F1: &str = "urn:oasis:names:tc:xacml:1.0:function:";
const F3: &str = "urn:oasis:names:tc:xacml:3.0:function:";

// The template's defaults, as its parameter rows give them.
const DEFAULT_OWNER_ROLE_ACTIONS: &str =
    "read, describe-role, add-member, remove-member, add-owner, remove-owner";
const DEFAULT_OWNER_GROUP_ACTIONS: &str =
    "read, add-member, add-owner, remove-owner";
const DEFAULT_OWNER_SERVICE_ACCOUNT_ACTIONS: &str =
    "read, add-service-account-owner, remove-service-account-owner, \
     set-service-account-destination, rotate-password";
const DEFAULT_OWNER_APPLICATION_ACTIONS: &str =
    "read, set, add, remove, update-fields, add-owner, remove-owner, \
     regenerate-secret, rotate-secret, add-secret, remove-secret, \
     owner-share, owner-unshare, owner-approve, owner-refuse";
const DEFAULT_OWNER_APPLICATION_ATTRIBUTES: &str =
    "appName, description, appHomePageUrl, appCorsOrigin, oauthRedirectUri, \
     oauthPostLogoutRedirectUri, oauthFrontchannelLogoutUri, \
     oauthBackchannelLogoutUri, samlAssertionConsumerService, \
     samlSingleLogoutService, oauthAllowedTokenResponseTypes";
const DEFAULT_REPORT_SHARED_ACTIONS: &str = "read, run";

/// `PolicyBuilders.listOf()`: commas or newlines, blanks dropped.
pub fn list_of(raw: &str) -> Vec<String> {
    raw.split([',', '\n'])
        .map(str::trim)
        .filter(|one| !one.is_empty())
        .map(str::to_string)
        .collect()
}

/// `PolicyBuilders.yes()`: anything that is not plainly a no is a yes; an
/// empty answer is the default.
pub fn yes(answer: &str, default: bool) -> bool {
    let text = answer.trim().to_lowercase();
    if text.is_empty() {
        return default;
    }
    !matches!(text.as_str(), "no" | "false" | "off" | "0" | "n")
}

/// `PolicyBuilders.slug()`: a lower-case, hyphen-separated identifier
/// fragment, or `x` when nothing is left.
pub fn slug(text: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in text.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if gap && !out.is_empty() {
                out.push('-');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
    }
    if out.is_empty() {
        "x".to_string()
    } else {
        out
    }
}

/// The template's parameters, each its default unless answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    /// The User Portal's rule — a CONSTRAINT: a resource naming an owner is
    /// reachable only by that owner. `false` refuses it to everybody.
    pub permit_owner: bool,
    /// A surface nobody has narrowed behaves as before there was a policy.
    pub permit_when_nothing_required: bool,
    /// An unauthenticated session is a subject; this keeps it out.
    pub require_authenticated: bool,
    /// The second rule (#607), and what an owner may do to each kind.
    pub permit_owner_administration: bool,
    pub owner_role_actions: Vec<String>,
    pub owner_group_actions: Vec<String>,
    pub owner_service_account_actions: Vec<String>,
    pub owner_application_actions: Vec<String>,
    pub owner_application_attributes: Vec<String>,
    /// The third rule (#1030).
    pub permit_report_sharing: bool,
    pub report_shared_actions: Vec<String>,
    /// The fourth rule (#1180).
    pub permit_access_request_approval: bool,
    pub permit_administrator_approval: bool,
    pub forbid_self_approval: bool,
}

impl Default for Parameters {
    fn default() -> Parameters {
        Parameters::from_answers(&BTreeMap::new())
    }
}

impl Parameters {
    /// `XacmlTemplates.build()`'s filling of the answers and the build
    /// function's reading of them: a missing or blank answer is the
    /// parameter's default, every answer trimmed, a yes/no read by [`yes`]
    /// and a list by [`list_of`].
    pub fn from_answers(answers: &BTreeMap<String, String>) -> Parameters {
        let filled = |name: &str, default: &str| -> String {
            match answers.get(name).map(|a| a.trim()) {
                Some(given) if !given.is_empty() => given.to_string(),
                _ => default.to_string(),
            }
        };
        let flag = |name: &str| yes(&filled(name, "yes"), true);
        let list = |name: &str, default: &str| list_of(&filled(name, default));
        Parameters {
            permit_owner: flag("permitOwner"),
            permit_when_nothing_required: flag("permitWhenNothingRequired"),
            require_authenticated: flag("requireAuthenticated"),
            permit_owner_administration: flag("permitOwnerAdministration"),
            owner_role_actions: list(
                "ownerRoleActions",
                DEFAULT_OWNER_ROLE_ACTIONS,
            ),
            owner_group_actions: list(
                "ownerGroupActions",
                DEFAULT_OWNER_GROUP_ACTIONS,
            ),
            owner_service_account_actions: list(
                "ownerServiceAccountActions",
                DEFAULT_OWNER_SERVICE_ACCOUNT_ACTIONS,
            ),
            owner_application_actions: list(
                "ownerApplicationActions",
                DEFAULT_OWNER_APPLICATION_ACTIONS,
            ),
            owner_application_attributes: list(
                "ownerApplicationAttributes",
                DEFAULT_OWNER_APPLICATION_ATTRIBUTES,
            ),
            permit_report_sharing: flag("permitReportSharing"),
            report_shared_actions: list(
                "reportSharedActions",
                DEFAULT_REPORT_SHARED_ACTIONS,
            ),
            permit_access_request_approval: flag("permitAccessRequestApproval"),
            permit_administrator_approval: flag("permitAdministratorApproval"),
            forbid_self_approval: flag("forbidSelfApproval"),
        }
    }
}

// ---------------------------------------------------------------------------
// The XML `PolicyBuilders`' nodes are written as — `apply`, `designator`,
// `value`, `match`, `targetOf` — read back by the crate's reader into the
// model Node's builders make.
// ---------------------------------------------------------------------------
fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// An Apply, the function named in full: `any-of` is 3.0 and `all-of-any`
/// 1.0, and the neighbouring namespace is the trap the template warns of.
fn apply(namespace: &str, function: &str, args: &[String]) -> String {
    format!(
        "<Apply FunctionId=\"{}{}\">{}</Apply>",
        namespace,
        function,
        args.concat()
    )
}

fn function(name: &str) -> String {
    format!("<Function FunctionId=\"{}{}\"/>", F1, name)
}

fn designator(cat: &str, id: &str, data_type: &str) -> String {
    format!(
        "<AttributeDesignator Category=\"{}\" AttributeId=\"{}\" \
         DataType=\"{}\" MustBePresent=\"false\"/>",
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

fn string(text: &str) -> String {
    value(types::STRING, text)
}

/// `integer-equal(string-bag-size(designator), 0)`: XACML cannot ask whether
/// a designator matched, so an absent attribute and one with no values are
/// the same empty bag.
fn empty(cat: &str, id: &str) -> String {
    apply(
        F1,
        "integer-equal",
        &[
            apply(F1, "string-bag-size", &[designator(cat, id, types::STRING)]),
            value(types::INTEGER, "0"),
        ],
    )
}

/// `any-of(boolean-equal, <expected>, designator)`: false for an absent
/// attribute as for the other value.
fn holds(cat: &str, id: &str, expected: &str) -> String {
    apply(
        F3,
        "any-of",
        &[
            function("boolean-equal"),
            value(types::BOOLEAN, expected),
            designator(cat, id, types::BOOLEAN),
        ],
    )
}

/// `any-of-any(string-equal, a, b)`: the two bags share a member.
fn share(a: String, b: String) -> String {
    apply(F3, "any-of-any", &[function("string-equal"), a, b])
}

/// `string-is-in(value, designator)`.
fn is_in(text: &str, cat: &str, id: &str) -> String {
    apply(
        F1,
        "string-is-in",
        &[string(text), designator(cat, id, types::STRING)],
    )
}

fn string_bag(values: &[String]) -> String {
    apply(
        F1,
        "string-bag",
        &values.iter().map(|v| string(v)).collect::<Vec<_>>(),
    )
}

/// `PolicyBuilders.targetOf()` of single-match groups: one `<AnyOf>` per
/// group, each holding one `<AllOf>` per alternative.
fn target_of(groups: &[Vec<(&str, &str, &str)>]) -> String {
    let any_of: String = groups
        .iter()
        .map(|group| {
            let all_of: String = group
                .iter()
                .map(|(literal, cat, id)| {
                    format!(
                        "<AllOf><Match MatchId=\"{}string-equal\">{}{}\
                         </Match></AllOf>",
                        F1,
                        string(literal),
                        designator(cat, id, types::STRING)
                    )
                })
                .collect();
            format!("<AnyOf>{}</AnyOf>", all_of)
        })
        .collect();
    format!("<Target>{}</Target>", any_of)
}

fn rule(id: &str, description: &str, target: &str, condition: &str) -> String {
    format!(
        "<Rule RuleId=\"{}\" Effect=\"Permit\"><Description>{}</Description>\
         {}<Condition>{}</Condition></Rule>",
        esc(id),
        esc(description),
        target,
        condition
    )
}

/// The first rule's condition.
fn may_reach_it(p: &Parameters) -> String {
    let s = category::ACCESS_SUBJECT;
    let r = category::RESOURCE;
    let holds_required_role = share(
        designator(s, vocabulary::ROLE, types::STRING),
        designator(r, REQUIRED_ROLE, types::STRING),
    );
    let mut role_arms = vec![holds_required_role];
    if p.permit_when_nothing_required {
        role_arms.push(empty(r, REQUIRED_ROLE));
    }
    let satisfies_role = if role_arms.len() == 1 {
        role_arms.remove(0)
    } else {
        apply(F1, "or", &role_arms)
    };
    let ownerless = empty(r, OWNER);
    let is_the_owner = share(
        designator(s, attribute::SUBJECT_ID, types::STRING),
        designator(r, OWNER, types::STRING),
    );
    let satisfies_ownership = if p.permit_owner {
        apply(F1, "or", &[ownerless, is_the_owner])
    } else {
        ownerless
    };
    let mut conjuncts = Vec::new();
    if p.require_authenticated {
        // A precondition, not an alternative: holding a role must not admit
        // somebody who never signed in.
        conjuncts.push(holds(s, AUTHENTICATED, "true"));
    }
    conjuncts.push(satisfies_role);
    // EVERY ROLE NAMED AS REQUIRED-ALL (#454): `all-of-any` holds when each
    // is among the subject's, and vacuously for an empty bag.
    conjuncts.push(apply(
        F1,
        "all-of-any",
        &[
            function("string-equal"),
            designator(r, REQUIRED_ALL_ROLE, types::STRING),
            designator(s, vocabulary::ROLE, types::STRING),
        ],
    ));
    conjuncts.push(satisfies_ownership);
    // NEVER AN ACCESS REQUEST (#1180): a role its resource required would
    // otherwise let the holder approve their own request.
    conjuncts.push(apply(
        F1,
        "not",
        &[is_in(ACCESS_REQUEST, r, attribute::RESOURCE_ID)],
    ));
    apply(F1, "and", &conjuncts)
}

/// The second rule's condition (#607): every conjunct narrows, and each
/// fails closed on an empty bag.
fn owner_administers(p: &Parameters) -> String {
    let s = category::ACCESS_SUBJECT;
    let r = category::RESOURCE;
    let kinds: [(&str, &Vec<String>); 4] = [
        ("role", &p.owner_role_actions),
        ("group", &p.owner_group_actions),
        ("service-account", &p.owner_service_account_actions),
        ("application", &p.owner_application_actions),
    ];
    let admin_action =
        || designator(category::ACTION, ADMIN_ACTION, types::STRING);
    let action_arms: Vec<String> = kinds
        .iter()
        .filter(|(_, actions)| !actions.is_empty())
        .map(|(kind, actions)| {
            apply(
                F1,
                "and",
                &[
                    is_in(kind, r, OBJECT_KIND),
                    share(admin_action(), string_bag(actions)),
                ],
            )
        })
        .collect();
    let actions = match action_arms.len() {
        0 => value(types::BOOLEAN, "false"),
        1 => action_arms[0].clone(),
        _ => apply(F1, "or", &action_arms),
    };
    let attributes = if p.owner_application_attributes.is_empty() {
        empty(r, OBJECT_ATTRIBUTE)
    } else {
        apply(
            F1,
            "all-of-any",
            &[
                function("string-equal"),
                designator(r, OBJECT_ATTRIBUTE, types::STRING),
                string_bag(&p.owner_application_attributes),
            ],
        )
    };
    // NEVER THE LAST OWNER (rcbj's decision 3 on #607).
    let removals = [
        "remove-owner".to_string(),
        "remove-service-account-owner".to_string(),
    ];
    let not_the_last = apply(
        F1,
        "or",
        &[
            apply(F1, "not", &[share(admin_action(), string_bag(&removals))]),
            apply(
                F1,
                "integer-greater-than",
                &[
                    apply(
                        F1,
                        "string-bag-size",
                        &[designator(r, OBJECT_OWNER, types::STRING)],
                    ),
                    value(types::INTEGER, "1"),
                ],
            ),
        ],
    );
    apply(
        F1,
        "and",
        &[
            holds(s, AUTHENTICATED, "true"),
            share(
                designator(s, vocabulary::ROLE, types::STRING),
                designator(r, OWNER_REQUIRED_ROLE, types::STRING),
            ),
            holds(r, OBJECT_PROTECTED, "false"),
            share(
                designator(s, OWNER_IDENTITY, types::STRING),
                designator(r, OBJECT_OWNER, types::STRING),
            ),
            actions,
            attributes,
            not_the_last,
        ],
    )
}

/// The third rule's condition (#1030).
fn report_rule(p: &Parameters) -> String {
    let s = category::ACCESS_SUBJECT;
    let r = category::RESOURCE;
    let shared_actions = if p.report_shared_actions.is_empty() {
        value(types::BOOLEAN, "false")
    } else {
        share(
            designator(category::ACTION, attribute::ACTION_ID, types::STRING),
            string_bag(&p.report_shared_actions),
        )
    };
    let shared_with_their_group = apply(
        F1,
        "and",
        &[
            shared_actions,
            share(
                designator(s, OWNER_IDENTITY, types::STRING),
                designator(r, REPORT_SHARED_GROUP, types::STRING),
            ),
        ],
    );
    apply(
        F1,
        "and",
        &[
            holds(s, AUTHENTICATED, "true"),
            share(
                designator(s, vocabulary::ROLE, types::STRING),
                designator(r, REQUIRED_ROLE, types::STRING),
            ),
            is_in("user", s, vocabulary::SUBJECT_KIND),
            apply(
                F1,
                "or",
                &[
                    is_in("REPORT_ADMIN", s, vocabulary::ROLE),
                    shared_with_their_group,
                ],
            ),
        ],
    )
}

/// The fourth rule's condition (#1180).
fn approval_rule(p: &Parameters) -> String {
    let s = category::ACCESS_SUBJECT;
    let r = category::RESOURCE;
    let named = holds(s, APPROVER_ELIGIBLE, "true");
    let administrator = apply(
        F1,
        "and",
        &[
            is_in("admin-api", category::ENVIRONMENT, APPROVER_DOOR),
            is_in("ADMIN_WRITE", s, vocabulary::ROLE),
        ],
    );
    let not_them = |id: &str| {
        apply(
            F1,
            "not",
            &[share(
                designator(s, APPROVER_IDENTITY, types::STRING),
                designator(r, id, types::STRING),
            )],
        )
    };
    let mut conjuncts = vec![
        holds(s, AUTHENTICATED, "true"),
        if p.permit_administrator_approval {
            apply(F1, "or", &[named, administrator])
        } else {
            named
        },
    ];
    if p.forbid_self_approval {
        conjuncts.push(not_them(ACCESS_REQUEST_SUBJECT));
        conjuncts.push(not_them(ACCESS_REQUEST_REQUESTER));
    }
    apply(F1, "and", &conjuncts)
}

/// The policy's Description, clause by clause as `buildAccessControl()`
/// assembles it.
fn policy_description(p: &Parameters) -> String {
    let mut text = String::from(
        "THE ACCESS-CONTROL POLICY. The embedded PEP asks this before a \
         subject reaches the admin console, the management API, the User \
         Portal, SCIM or the SPIRE Server API. It permits when the subject \
         satisfies the resource's ROLE requirement — holding a role it \
         requires",
    );
    if p.permit_when_nothing_required {
        text.push_str(", or the resource requiring none");
    }
    text.push_str(
        " — AND holds EVERY role it names as required-all, where it names \
         any, AND satisfies its OWNERSHIP requirement: the resource names no \
         owner",
    );
    if p.permit_owner {
        text.push_str(
            ", or the subject IS that owner, which is how a person reaches \
             their own account and nobody else's",
        );
    }
    if p.require_authenticated {
        text.push_str(
            ". A subject that did not authenticate is refused whatever else \
             is true",
        );
    }
    if p.permit_owner_administration {
        text.push_str(
            ". A second rule (#607) permits an OWNER to administer what they \
             own through the management API, within the actions its kind \
             allows",
        );
    }
    if p.permit_report_sharing {
        text.push_str(
            ". A third rule (#1030) permits a report administrator any \
             report definition or job, and a shared group's member the \
             listed actions on one shared with them",
        );
    }
    if p.permit_access_request_approval {
        text.push_str(
            ". A fourth rule (#1180) permits the approvers an AuthZEN access \
             request names to decide it, and the first rule never permits \
             that resource",
        );
    }
    text.push_str(
        ". Everything else is denied: the combining algorithm is \
         deny-unless-permit, so an access decision does not depend on a \
         PEP's bias.",
    );
    text
}

/// `buildAccessControl()`, as XACML 3.0 XML, for the policy named `name`:
/// its PolicyId is `urn:sts:xacml:policy:` and the name's [`slug`], as
/// `XacmlTemplates.build()` makes it.
pub fn document(name: &str, p: &Parameters) -> String {
    let id = format!("urn:sts:xacml:policy:{}", slug(name));
    let r = category::RESOURCE;
    let mut rules = rule(
        &format!("{}:rule:may-reach-it", id),
        "Permit when the subject satisfies the resource's role requirement \
         AND its ownership requirement. Ownership is a constraint rather \
         than a way round the roles: a resource that names an owner is \
         reachable only by that owner.",
        "",
        &may_reach_it(p),
    );
    if p.permit_owner_administration {
        rules.push_str(&rule(
            &format!("{}:rule:owner-administers-what-they-own", id),
            "Permit an OWNER (#607) to read or change, through the \
             management API, a role, group, service account or application \
             whose owners name them or a group they are in: holding the \
             owner role the operation names, the object not closed to its \
             owners, the action one this kind allows, every attribute \
             written one an owner may write, and never the last owner taken \
             off.",
            "",
            &owner_administers(p),
        ));
    }
    if p.permit_report_sharing {
        let shared = if p.report_shared_actions.is_empty() {
            "(none)".to_string()
        } else {
            p.report_shared_actions.join(", ")
        };
        rules.push_str(&rule(
            &format!("{}:rule:report-administrators-and-shares", id),
            &format!(
                "Permit a PERSON holding REPORT_ADMIN any report definition \
                 or job of the realm, and a person holding a report role the \
                 actions {} on one shared with a group they are in (#1030). \
                 An owner reaches their own through the first rule; an \
                 application reaches only what it defined.",
                shared
            ),
            &target_of(&[vec![(REPORT_API, r, attribute::RESOURCE_ID)]]),
            &report_rule(p),
        ));
    }
    if p.permit_access_request_approval {
        let mut description = String::from(
            "Permit a person to approve, deny or revoke an AuthZEN access \
             request (#1180) when the denying policy's advice named them — \
             its approver role, its approver group, or the application's \
             owners",
        );
        if p.permit_administrator_approval {
            description.push_str(
                " — or they hold ADMIN_WRITE and act through the management \
                 API",
            );
        }
        if p.forbid_self_approval {
            description.push_str(
                ", and none of their names is the request's subject or the \
                 PEP that asked it",
            );
        }
        description.push('.');
        rules.push_str(&rule(
            &format!("{}:rule:access-request-approvers", id),
            &description,
            &target_of(&[
                vec![(ACCESS_REQUEST, r, attribute::RESOURCE_ID)],
                vec![(
                    APPROVE_ACCESS_REQUEST,
                    category::ACTION,
                    attribute::ACTION_ID,
                )],
            ]),
            &approval_rule(p),
        ));
    }
    format!(
        "<Policy xmlns=\"{ns}\" PolicyId=\"{id}\" Version=\"1.0\" \
         RuleCombiningAlgId=\"{alg}\"><Description>{description}\
         </Description><Target/>{rules}</Policy>",
        ns = NS_XACML,
        id = esc(&id),
        alg = rule_alg::DENY_UNLESS_PERMIT,
        description = esc(&policy_description(p)),
        rules = rules
    )
}

/// The built-in document, read.
pub fn built_in(name: &str, p: &Parameters) -> XacmlResult<PolicyNode> {
    crate::xml::parse_policy(&document(name, p))
}

/// The object an owner would administer (#607): `common/access_gate.ts`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OwnedObject {
    /// `role`, `group`, `service-account` or `application`.
    pub kind: String,
    pub id: String,
    /// `read`, or the management API action's own name.
    pub action: String,
    /// OWNER_READ or OWNER_WRITE.
    pub required_role: String,
    /// What an application action would write, by name.
    pub attributes: Vec<String>,
    /// The person the token is for, by username.
    pub person: String,
}

/// A report definition or job (#1030).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReportObject {
    /// `definition` or `job`.
    pub kind: String,
    pub owner: String,
    pub groups: Vec<String>,
    pub person: String,
}

/// An AuthZEN access request being decided (#1180).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AccessRequestObject {
    pub id: String,
    pub requester: String,
    pub subject: String,
    pub subject_type: String,
    pub action: String,
    pub resource: String,
    pub resource_type: String,
    pub application: String,
    /// Whether the policy's advice named the approver.
    pub eligible: bool,
    /// `portal` or `admin-api`.
    pub door: String,
    pub approver_identity: Vec<String>,
}

/// What is asked: a resource, an action, the owner where the resource has
/// one, and the subject — with whatever object the owner, report or access
/// request rule decides on.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Question {
    pub resource: String,
    pub action: String,
    pub owner: Option<String>,
    /// Empty for an unauthenticated caller.
    pub subject: String,
    /// How the subject is named in a refusal, where not by its name.
    pub label: String,
    /// `user` or `application`, sent only when the caller said (the report
    /// gate does); anything but `application` is a person.
    pub kind: Option<String>,
    pub authenticated: bool,
    /// Roles the subject must hold every one of (#454).
    pub required_all_roles: Vec<String>,
    pub owned_object: Option<OwnedObject>,
    pub report_object: Option<ReportObject>,
    pub access_request_object: Option<AccessRequestObject>,
}

/// `buildRequest()`: through the one builder, an empty value left out of
/// its bag, so an ownerless surface sends no owner rather than one called "".
pub fn request(q: &Question, held: &[String], required: &[String]) -> Request {
    let mut r = AuthorizationRequest::new(true, true, true);
    let kind = q.kind.as_deref().map(|k| {
        if k == "application" {
            "application"
        } else {
            "user"
        }
    });
    let all = |values: &[String]| values.to_vec();
    r.principal(&q.subject, kind)
        .roles(all(held))
        .subject(AUTHENTICATED, [q.authenticated])
        .target(&q.resource, None)
        .resource(REQUIRED_ROLE, all(required))
        .resource(REQUIRED_ALL_ROLE, all(&q.required_all_roles))
        .resource(OWNER, [q.owner.clone().unwrap_or_default()])
        .requested_action(&q.action);
    // THE OWNER RULE'S QUESTION (#607): who owns it, whether it is closed
    // to its owners and who the person is as an owner are the PIP's.
    if let Some(owned) = q
        .owned_object
        .as_ref()
        .filter(|o| !o.kind.is_empty() && !o.id.is_empty())
    {
        r.resource(OWNER_REQUIRED_ROLE, [owned.required_role.as_str()])
            .resource(OBJECT_KIND, [owned.kind.as_str()])
            .resource(OBJECT_ID, [owned.id.as_str()])
            .resource(OBJECT_ATTRIBUTE, all(&owned.attributes))
            .action(ADMIN_ACTION, [owned.action.as_str()])
            .subject(OWNER_SUBJECT, [owned.person.as_str()]);
    }
    // THE REPORT RULE'S QUESTION (#1030); the row's owner is `owner` above.
    if let Some(row) = q.report_object.as_ref().filter(|o| !o.kind.is_empty()) {
        r.resource(REPORT_OBJECT_KIND, [row.kind.as_str()])
            .resource(REPORT_SHARED_GROUP, all(&row.groups))
            .subject(OWNER_SUBJECT, [row.person.as_str()]);
    }
    // THE ACCESS REQUEST RULE'S QUESTION (#1180).
    if let Some(ask) = q
        .access_request_object
        .as_ref()
        .filter(|o| !o.id.is_empty())
    {
        r.resource(ACCESS_REQUEST_ID, [ask.id.as_str()])
            .resource(ACCESS_REQUEST_REQUESTER, [ask.requester.as_str()])
            .resource(ACCESS_REQUEST_SUBJECT, [ask.subject.as_str()])
            .resource(ACCESS_REQUEST_SUBJECT_TYPE, [ask.subject_type.as_str()])
            .resource(ACCESS_REQUEST_ACTION, [ask.action.as_str()])
            .resource(ACCESS_REQUEST_RESOURCE, [ask.resource.as_str()])
            .resource(
                ACCESS_REQUEST_RESOURCE_TYPE,
                [ask.resource_type.as_str()],
            )
            .resource(ACCESS_REQUEST_APPLICATION, [ask.application.as_str()])
            .subject(APPROVER_ELIGIBLE, [ask.eligible])
            .subject(APPROVER_IDENTITY, all(&ask.approver_identity))
            .environment(APPROVER_DOOR, [ask.door.as_str()]);
    }
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

/// `decide()`'s evaluation and wording, for a policy already loaded, with
/// no PIP. `held` is what the subject holds, the caller's own roles
/// included; `required` what the resource requires.
pub fn decide(
    policy: &PolicyNode,
    q: &Question,
    held: &[String],
    required: &[String],
) -> Answer {
    decide_with(policy, q, held, required, &EvaluationOptions::default())
}

/// [`decide`], with the PIP and repository the runtime evaluates with.
pub fn decide_with(
    policy: &PolicyNode,
    q: &Question,
    held: &[String],
    required: &[String],
    options: &EvaluationOptions<'_>,
) -> Answer {
    let response =
        Pdp::new().evaluate(policy, &request(q, held, required), options);
    if response.decision == Decision::Permit {
        return Answer {
            allowed: true,
            decision: response.decision,
            refused: None,
            why: "The access policy permitted it.".into(),
        };
    }
    let name = if q.label.is_empty() {
        &q.subject
    } else {
        &q.label
    };
    let who = if name.is_empty() {
        "an unauthenticated caller".to_string()
    } else {
        format!(
            "\"{}\"{}",
            name,
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
            .filter(|o| !o.is_empty())
            .map(|o| format!(", owned by \"{}\"", o))
            .unwrap_or_default()
    );
    let (refused, why) = match response.decision {
        Decision::Deny => (
            Refused::Deny,
            format!(
                "The access policy denied {} for {}. They hold {}; it \
                 requires {}.",
                what,
                who,
                if held.is_empty() {
                    "no role".to_string()
                } else {
                    held.join(", ")
                },
                if required.is_empty() {
                    "nothing".to_string()
                } else {
                    required.join(" or ")
                }
            ),
        ),
        Decision::NotApplicable => (
            Refused::NotApplicable,
            format!(
                "The access policy did not cover {}, and its combining \
                 algorithm is deny-unless-permit — so a question it does not \
                 answer is a refusal rather than a permission.",
                what
            ),
        ),
        _ => (
            Refused::Indeterminate,
            format!(
                "The access policy could not be evaluated for {} ({}), which \
                 is a fault in the policy rather than a decision about {}.",
                what,
                response
                    .status
                    .message
                    .clone()
                    .unwrap_or_else(|| "no reason given".into()),
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
