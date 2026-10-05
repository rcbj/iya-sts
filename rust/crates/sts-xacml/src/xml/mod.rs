// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XACML 3.0 core XML, read into the model and a policy written back out. A
//! port of `xacml/xacml_xml.js`: the reader here, the writer — which the
//! PAP's editor and the ALFA import need — in `writer.rs`, whose output was
//! compared with the Node writer's over every policy of the OASIS suite and
//! is identical byte for byte (484 documents, 2026-10-05).
//!
//! **The parser is deliberately strict.** Six conformance cases carry an
//! invalid POLICY and assert that loading it FAILS; a permissive reader would
//! load them and pass for the wrong reason. The one deliberate looseness is
//! the XML NAMESPACE: elements are matched on local name, because documents
//! in the wild carry the 3.0 namespace, the 2.0 one, or none.
//!
//! **An `AttributeValue` is not parsed here.** It is carried as its lexical
//! form and parsed at evaluation, so a bad one is an Indeterminate for a
//! request rather than a policy that will not load.
//!
//! The DOM is `roxmltree`, which refuses a DTD by default — so no external
//! entity is ever resolved and no entity expansion can be used against the
//! PDP.

mod reader;
mod writer;

pub use reader::{
    parse_policy, parse_policy_unchecked, parse_request, parse_response,
    read_request, ExpectedResponse, ExpectedResult,
};
pub use writer::{escape, write_policy};
