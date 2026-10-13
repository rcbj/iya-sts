// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The vocabulary every other module in this crate agrees about: the
//! identifiers the specification fixes, the seven decision values, bags, and
//! the error an Indeterminate is raised as. Nothing in here parses.
//!
//! A port of `xacml/xacml_model.js`. That file's header argues the two rules
//! this one keeps, and they are repeated here because a reader of the Rust
//! will not have the JavaScript open:
//!
//! * **There is ONE model.** The XML reader (and later the JSON Profile and
//!   ALFA) read INTO it, and the PDP evaluates it. Nothing downstream may ask
//!   which syntax a policy arrived in.
//! * **The four decisions are seven.** XACML 3.0 splits Indeterminate into
//!   Indeterminate{P}, {D} and {DP}, and the combining algorithms depend on
//!   the split. Collapse them and `deny-overrides` returns Permit where the
//!   specification says Deny. They are folded back to four exactly once, at
//!   the edge, by [`Decision::external`].
//!
//! Every identifier is spelt out in full rather than built by concatenation:
//! the URIs differ in one segment (`1.0` against `3.0`), and a joined one
//! looks right in the source, matches nothing, and fails as NotApplicable.

use std::fmt;

use crate::value::Value;

/// The seven XACML 3.0 decision values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    Permit,
    Deny,
    NotApplicable,
    Indeterminate,
    /// Could only have been Permit.
    IndeterminateP,
    /// Could only have been Deny.
    IndeterminateD,
    /// Could have been either.
    IndeterminateDP,
}

impl Decision {
    /// The specification's own spelling, braces included, so a decision in a
    /// log or a test failure is the string the specification uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Permit => "Permit",
            Decision::Deny => "Deny",
            Decision::NotApplicable => "NotApplicable",
            Decision::Indeterminate => "Indeterminate",
            Decision::IndeterminateP => "Indeterminate{P}",
            Decision::IndeterminateD => "Indeterminate{D}",
            Decision::IndeterminateDP => "Indeterminate{DP}",
        }
    }

    /// Reads one of the four EXTERNAL decisions, as a Response carries them.
    pub fn from_external(text: &str) -> Option<Decision> {
        match text {
            "Permit" => Some(Decision::Permit),
            "Deny" => Some(Decision::Deny),
            "NotApplicable" => Some(Decision::NotApplicable),
            "Indeterminate" => Some(Decision::Indeterminate),
            _ => None,
        }
    }

    /// Folds an extended Indeterminate down to the plain one a Response
    /// carries. Called ONCE, at the edge of the PDP (`Pdp::evaluate`); a
    /// second call site inside the evaluation is the defect the module header
    /// warns about.
    pub fn external(self) -> Decision {
        if self.is_indeterminate() {
            Decision::Indeterminate
        } else {
            self
        }
    }

    /// True for Indeterminate and its three extended forms.
    pub fn is_indeterminate(self) -> bool {
        matches!(
            self,
            Decision::Indeterminate
                | Decision::IndeterminateP
                | Decision::IndeterminateD
                | Decision::IndeterminateDP
        )
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Rule's Effect; an obligation or advice fires on one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Permit,
    Deny,
}

impl Effect {
    pub fn parse(text: &str) -> Option<Effect> {
        match text {
            "Permit" => Some(Effect::Permit),
            "Deny" => Some(Effect::Deny),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Permit => "Permit",
            Effect::Deny => "Deny",
        }
    }

    /// The decision a fired Rule of this Effect produces.
    pub fn decision(self) -> Decision {
        match self {
            Effect::Permit => Decision::Permit,
            Effect::Deny => Decision::Deny,
        }
    }

    /// Section 7.11: a Rule that cannot be evaluated is Indeterminate in the
    /// direction of its OWN Effect, because that is the only decision it could
    /// ever have produced. One line, and the reason the extended values exist.
    pub fn indeterminate(self) -> Decision {
        match self {
            Effect::Permit => Decision::IndeterminateP,
            Effect::Deny => Decision::IndeterminateD,
        }
    }
}

/// What a Target says: in scope, out of scope, or unknown because an
/// attribute lookup failed. Not a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    Match,
    NoMatch,
    Indeterminate,
}

/// The XACML status codes (section 5.57). Each says WHY there is no
/// decision, which is the half of an Indeterminate that makes it debuggable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Ok,
    MissingAttribute,
    SyntaxError,
    ProcessingError,
}

impl StatusCode {
    pub fn uri(self) -> &'static str {
        match self {
            StatusCode::Ok => "urn:oasis:names:tc:xacml:1.0:status:ok",
            StatusCode::MissingAttribute => {
                "urn:oasis:names:tc:xacml:1.0:status:missing-attribute"
            }
            StatusCode::SyntaxError => {
                "urn:oasis:names:tc:xacml:1.0:status:syntax-error"
            }
            StatusCode::ProcessingError => {
                "urn:oasis:names:tc:xacml:1.0:status:processing-error"
            }
        }
    }
}

/// The standard attribute categories. The access-subject category kept its
/// `1.0` `subject-category` prefix while resource, action and environment
/// moved to `3.0:attribute-category` — the specification's inconsistency,
/// not a typo. Do not tidy them.
pub mod category {
    pub const ACCESS_SUBJECT: &str =
        "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
    pub const RECIPIENT_SUBJECT: &str =
        "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";
    pub const INTERMEDIARY_SUBJECT: &str =
        "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject";
    pub const CODEBASE: &str =
        "urn:oasis:names:tc:xacml:1.0:subject-category:codebase";
    pub const REQUESTING_MACHINE: &str =
        "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine";
    pub const RESOURCE: &str =
        "urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
    pub const ACTION: &str =
        "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
    pub const ENVIRONMENT: &str =
        "urn:oasis:names:tc:xacml:3.0:attribute-category:environment";
}

/// The standard attribute identifiers something here reaches for by name.
/// The three `current-*` values are the ones the PDP must be able to SUPPLY
/// when a request does not carry them (section 10.2.5).
pub mod attribute {
    pub const SUBJECT_ID: &str =
        "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
    pub const RESOURCE_ID: &str =
        "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
    pub const ACTION_ID: &str = "urn:oasis:names:tc:xacml:1.0:action:action-id";
    pub const CURRENT_TIME: &str =
        "urn:oasis:names:tc:xacml:1.0:environment:current-time";
    pub const CURRENT_DATE: &str =
        "urn:oasis:names:tc:xacml:1.0:environment:current-date";
    pub const CURRENT_DATETIME: &str =
        "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";
}

/// The seventeen datatype URIs: twelve XML Schema types and XACML's own five.
pub mod types {
    pub const STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
    pub const BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
    pub const INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
    pub const DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
    pub const TIME: &str = "http://www.w3.org/2001/XMLSchema#time";
    pub const DATE: &str = "http://www.w3.org/2001/XMLSchema#date";
    pub const DATETIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
    pub const DAYTIME_DURATION: &str =
        "http://www.w3.org/2001/XMLSchema#dayTimeDuration";
    pub const YEARMONTH_DURATION: &str =
        "http://www.w3.org/2001/XMLSchema#yearMonthDuration";
    pub const ANYURI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
    pub const HEXBINARY: &str = "http://www.w3.org/2001/XMLSchema#hexBinary";
    pub const BASE64BINARY: &str =
        "http://www.w3.org/2001/XMLSchema#base64Binary";
    pub const RFC822NAME: &str =
        "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
    pub const X500NAME: &str =
        "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";
    pub const DNSNAME: &str = "urn:oasis:names:tc:xacml:2.0:data-type:dnsName";
    pub const IPADDRESS: &str =
        "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress";
    pub const XPATH_EXPRESSION: &str =
        "urn:oasis:names:tc:xacml:3.0:data-type:xpathExpression";

    /// The pre-3.0 XQuery spellings of the two duration types. Accepted on
    /// the way IN (several conformance cases still carry them) and never
    /// written out.
    pub const LEGACY_DAYTIME_DURATION: &str =
        "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#dayTimeDuration";
    pub const LEGACY_YEARMONTH_DURATION: &str =
        "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#yearMonthDuration";
}

/// The rule-combining algorithm identifiers, 3.0 and legacy.
pub mod rule_alg {
    pub const DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides";
    pub const PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides";
    pub const ORDERED_DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-deny-overrides";
    pub const ORDERED_PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:ordered-permit-overrides";
    pub const DENY_UNLESS_PERMIT: &str =
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit";
    pub const PERMIT_UNLESS_DENY: &str =
        "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-unless-deny";
    pub const FIRST_APPLICABLE: &str =
        "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable";
    pub const LEGACY_DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides";
    pub const LEGACY_PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides";
    pub const LEGACY_ORDERED_DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-deny-overrides";
    pub const LEGACY_ORDERED_PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.1:rule-combining-algorithm:ordered-permit-overrides";
}

/// The policy-combining algorithm identifiers, 3.0 and legacy, with
/// only-one-applicable.
pub mod policy_alg {
    pub const DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides";
    pub const PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides";
    pub const ORDERED_DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:ordered-deny-overrides";
    pub const ORDERED_PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:ordered-permit-overrides";
    pub const DENY_UNLESS_PERMIT: &str =
        "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-unless-permit";
    pub const PERMIT_UNLESS_DENY: &str =
        "urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-unless-deny";
    pub const FIRST_APPLICABLE: &str =
        "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:first-applicable";
    pub const ONLY_ONE_APPLICABLE: &str =
        "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:only-one-applicable";
    pub const LEGACY_DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:deny-overrides";
    pub const LEGACY_PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:permit-overrides";
    pub const LEGACY_ORDERED_DENY_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:ordered-deny-overrides";
    pub const LEGACY_ORDERED_PERMIT_OVERRIDES: &str =
        "urn:oasis:names:tc:xacml:1.1:policy-combining-algorithm:ordered-permit-overrides";
}

/// The XACML 3.0 core XML namespace. The `wd-17` is the OASIS standard's own
/// namespace, not a leftover working draft.
pub const NS_XACML: &str = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";

/// A datatype URI with the two legacy duration spellings mapped to their XML
/// Schema URIs. One place, so "we accept the old namespace" is a fact about
/// this function rather than something every reader repeats.
pub fn canonical_type(uri: &str) -> &str {
    match uri {
        types::LEGACY_DAYTIME_DURATION => types::DAYTIME_DURATION,
        types::LEGACY_YEARMONTH_DURATION => types::YEARMONTH_DURATION,
        other => other,
    }
}

/// A bag: EVERY value in XACML is one. Unordered and keeping duplicates —
/// `bag-size` counts them, so it is a `Vec` and never a set. An
/// `AttributeValue` is a bag of one, so nothing here holds a bare value.
#[derive(Debug, Clone, PartialEq)]
pub struct Bag {
    /// The datatype URI, canonicalised by [`canonical_type`].
    pub type_uri: String,
    pub values: Vec<Value>,
}

impl Bag {
    pub fn new(type_uri: &str, values: Vec<Value>) -> Bag {
        Bag {
            type_uri: canonical_type(type_uri).to_string(),
            values,
        }
    }

    pub fn empty(type_uri: &str) -> Bag {
        Bag::new(type_uri, Vec::new())
    }

    pub fn singleton(type_uri: &str, value: Value) -> Bag {
        Bag::new(type_uri, vec![value])
    }

    pub fn boolean(value: bool) -> Bag {
        Bag::singleton(types::BOOLEAN, Value::Boolean(value))
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// The error every failure in this crate is raised as. It carries a STATUS
/// CODE, because "the policy is malformed", "an attribute the policy needs is
/// not there" and "something else went wrong" are the whole content of an
/// Indeterminate. Raised only where the answer becomes Indeterminate.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct XacmlError {
    pub status: StatusCode,
    pub message: String,
}

impl XacmlError {
    pub fn missing_attribute(message: impl Into<String>) -> XacmlError {
        XacmlError {
            status: StatusCode::MissingAttribute,
            message: message.into(),
        }
    }

    pub fn syntax(message: impl Into<String>) -> XacmlError {
        XacmlError {
            status: StatusCode::SyntaxError,
            message: message.into(),
        }
    }

    pub fn processing(message: impl Into<String>) -> XacmlError {
        XacmlError {
            status: StatusCode::ProcessingError,
            message: message.into(),
        }
    }
}

/// Every fallible operation in this crate.
pub type XacmlResult<T> = Result<T, XacmlError>;
