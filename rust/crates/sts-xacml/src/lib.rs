// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The XACML 3.0 engine — model, datatypes, function library, combining
//! algorithms, PDP, static validation and the XML reader — with no I/O. A
//! port of the eight engine files in `xacml/` (#444, phase 1).
//!
//! It is shared by the runtime's PDP and by the remote PEP container, as the
//! JavaScript engine is today: the PEP copies these files at build time,
//! and here it depends on this crate. Nothing in it may reach a socket, a
//! file or a clock other than through [`pdp::EvaluationOptions`].
//!
//! ```
//! use sts_xacml::{pdp::{EvaluationOptions, Pdp}, xml};
//!
//! let policy = xml::parse_policy(r#"
//!   <Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
//!           PolicyId="p" Version="1.0"
//!           RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit">
//!     <Target/>
//!     <Rule RuleId="r" Effect="Permit"/>
//!   </Policy>"#).unwrap();
//! let request = xml::parse_request(r#"
//!   <Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
//!            ReturnPolicyIdList="false" CombinedDecision="false"/>"#).unwrap();
//! let response = Pdp::new().evaluate(&policy, &request,
//!                                    &EvaluationOptions::default());
//! assert_eq!(response.decision.as_str(), "Permit");
//! ```

pub mod builder;
pub mod combining;
pub mod datatypes;
pub mod functions;
pub mod json;
pub mod model;
pub mod pdp;
pub mod policy;
pub mod request;
pub mod validate;
pub mod value;
pub mod xml;
