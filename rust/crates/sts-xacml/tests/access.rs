// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The built-in access-control policy, held to `tests/access_policy.js`'s
//! claims: ownership is a CONSTRAINT and not an alternative — a signed-in
//! person reaches their own portal account and not somebody else's, for
//! manage-own and for read — while the ownerless surfaces behave as plain
//! RBAC; each of the three parameters does what its help says; and each
//! kind of refusal carries its own code.

#![allow(clippy::unwrap_used)] // a test file

use sts_xacml::access::{
    built_in, decide, document, request, Parameters, Question, Refused, OWNER,
    REQUIRED_ROLE,
};
use sts_xacml::model::{category, Decision};

fn q(
    resource: &str,
    action: &str,
    owner: Option<&str>,
    subject: &str,
    authenticated: bool,
) -> Question {
    Question {
        resource: resource.into(),
        action: action.into(),
        owner: owner.map(str::to_string),
        subject: subject.into(),
        authenticated,
    }
}

fn s(list: &[&str]) -> Vec<String> {
    list.iter().map(|x| x.to_string()).collect()
}

#[test]
fn ownership_is_a_constraint_and_roles_are_rbac() {
    let policy = built_in("access-control", Parameters::default()).unwrap();
    // THE REGRESSION: the portal requires no role, and that must not admit
    // somebody else.
    for action in ["manage-own", "read"] {
        let own = decide(
            &policy,
            &q("portal", action, Some("alice"), "alice", true),
            &s(&[]),
            &s(&[]),
        );
        assert!(own.allowed, "{}: {}", action, own.why);
        let other = decide(
            &policy,
            &q("portal", action, Some("alice"), "bob", true),
            &s(&[]),
            &s(&[]),
        );
        assert!(!other.allowed, "{}: bob reached alice's account", action);
        assert_eq!(other.refused, Some(Refused::Deny));
        assert!(other.why.contains("owned by \"alice\""), "{}", other.why);
    }
    // Holding a role does not get round the owner.
    let admin = decide(
        &policy,
        &q("portal", "read", Some("alice"), "carol", true),
        &s(&["ADMIN_WRITE"]),
        &s(&[]),
    );
    assert!(!admin.allowed);
    // The console: RBAC.
    let required = s(&["ADMIN_READ", "ADMIN_WRITE"]);
    let reader = decide(
        &policy,
        &q("admin-console", "read", None, "alice", true),
        &s(&["ADMIN_READ"]),
        &required,
    );
    assert!(reader.allowed, "{}", reader.why);
    let nobody = decide(
        &policy,
        &q("admin-console", "read", None, "bob", true),
        &s(&["EVERYBODY"]),
        &required,
    );
    assert_eq!((nobody.allowed, nobody.decision), (false, Decision::Deny));
    assert_eq!(nobody.refused.unwrap().code(), "STS-XACML-0044");
    assert!(
        nobody.why.contains(
            "They hold EVERYBODY; it requires ADMIN_READ or ADMIN_WRITE."
        ),
        "{}",
        nobody.why
    );
    // A surface nobody narrowed admits anybody who signed in, and nobody who
    // did not.
    assert!(
        decide(
            &policy,
            &q("scim", "write", None, "bob", true),
            &s(&[]),
            &s(&[])
        )
        .allowed
    );
    let anon = decide(
        &policy,
        &q("scim", "write", None, "anonymous", false),
        &s(&[]),
        &s(&[]),
    );
    assert!(!anon.allowed);
    assert!(anon.why.contains("(who did not authenticate)"));
    let none = decide(
        &policy,
        &q("scim", "write", None, "", false),
        &s(&[]),
        &s(&[]),
    );
    assert!(none.why.contains("an unauthenticated caller"));
}

#[test]
fn each_parameter_does_what_it_says() {
    let no_owner = built_in(
        "p",
        Parameters {
            permit_owner: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !decide(
            &no_owner,
            &q("portal", "read", Some("alice"), "alice", true),
            &s(&[]),
            &s(&[])
        )
        .allowed
    );
    assert!(
        decide(
            &no_owner,
            &q("scim", "read", None, "alice", true),
            &s(&[]),
            &s(&[])
        )
        .allowed
    );
    let closed = built_in(
        "p",
        Parameters {
            permit_when_nothing_required: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !decide(
            &closed,
            &q("scim", "read", None, "alice", true),
            &s(&[]),
            &s(&[])
        )
        .allowed
    );
    assert!(
        decide(
            &closed,
            &q("scim", "read", None, "alice", true),
            &s(&["SCIM"]),
            &s(&["SCIM"])
        )
        .allowed
    );
    let open = built_in(
        "p",
        Parameters {
            require_authenticated: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        decide(
            &open,
            &q("scim", "read", None, "anonymous", false),
            &s(&[]),
            &s(&[])
        )
        .allowed
    );
}

#[test]
fn the_request_and_the_other_refusals() {
    // An ownerless surface sends no owner, and nothing required no role.
    let r =
        request(&q("scim", "read", None, "alice", true), &s(&["A"]), &s(&[]));
    let resource = r
        .categories
        .iter()
        .find(|c| c.category == category::RESOURCE)
        .unwrap();
    for id in [OWNER, REQUIRED_ROLE] {
        assert!(
            resource
                .attributes
                .iter()
                .all(|a| a.attribute_id != id || a.values.is_empty()),
            "{} sent empty",
            id
        );
    }
    // A document that cannot be evaluated is a fault, not a decision: the
    // 1.0 namespace for any-of names a function nothing implements.
    // Under the built-in deny-unless-permit that is a Deny (what Node's
    // template comment warns of); an override combining otherwise is where
    // an Indeterminate reaches the PEP.
    let broken = document("broken", Parameters::default()).replace(
        "urn:oasis:names:tc:xacml:3.0:function:any-of\"",
        "urn:oasis:names:tc:xacml:1.0:function:any-of\"",
    );
    let as_deny = sts_xacml::xml::parse_policy_unchecked(&broken).unwrap();
    let a = decide(
        &as_deny,
        &q("scim", "read", None, "alice", true),
        &s(&[]),
        &s(&[]),
    );
    assert_eq!(a.refused, Some(Refused::Deny));
    let broken = broken.replace(
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit",
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides",
    );
    let indeterminate =
        sts_xacml::xml::parse_policy_unchecked(&broken).unwrap();
    let a = decide(
        &indeterminate,
        &q("scim", "read", None, "alice", true),
        &s(&[]),
        &s(&[]),
    );
    assert_eq!(a.refused, Some(Refused::Indeterminate), "{:?}", a);
    assert_eq!(a.refused.unwrap().code(), "STS-XACML-0045");
    // An override that answers nothing is a refusal too.
    let silent = sts_xacml::xml::parse_policy(&format!(
        "<Policy xmlns=\"{}\" PolicyId=\"silent\" Version=\"1.0\" \
         RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\"><Target/></Policy>",
        sts_xacml::model::NS_XACML
    ))
    .unwrap();
    let a = decide(
        &silent,
        &q("scim", "read", None, "alice", true),
        &s(&[]),
        &s(&[]),
    );
    assert_eq!(
        (a.decision, a.refused),
        (Decision::NotApplicable, Some(Refused::NotApplicable))
    );
    assert_eq!(a.refused.unwrap().code(), "STS-XACML-0046");
    // A name with markup in it is the policy's id, not markup.
    let named = built_in("a\"<b>&c", Parameters::default()).unwrap();
    assert_eq!(named.id(), "a\"<b>&c");
}
