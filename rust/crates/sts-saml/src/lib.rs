// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SAML 2.0 AS AN IDENTITY PROVIDER (`saml/saml2_sso.ts` and its
//! libraries), ported for the #444 Rust runtime, phase 7.
//!
//! | Module | Node |
//! |---|---|
//! | [`model`] | `saml/saml_model.ts` over `models/generated/saml.json` |
//! | [`authn_context`] | `saml/authn_context.ts` |
//! | [`assertion`] | `saml/saml2.ts`'s `buildSamlAssertion()`, `signAssertion()` |
//! | [`response`] | `saml2_sso.ts`'s `statusElement()`, `buildResponse()` |
//! | [`binding`] | the bindings: decoding, Redirect, SimpleSign, the POST page |
//! | [`request`] | `readAuthnRequest()` and `validation.parseXml()` |
//! | [`artifact`] | `mintArtifact()`, `isForeignArtifact()`, the stored row |
//! | [`sp_signature`] | `saml/request_signature.ts` |
//!
//! Each is a library: no route, no store of its own. The runtime declares
//! the stores under Node's handles and wires the endpoints
//! (`bins/sts-runtime`), so a row a 1.x install wrote is read as Node wrote
//! it (D11).

#![forbid(unsafe_code)]

pub mod artifact;
pub mod assertion;
pub mod authn_context;
pub mod binding;
pub mod metadata;
pub mod model;
pub mod request;
pub mod response;
pub mod saml11;
pub mod sp_signature;
