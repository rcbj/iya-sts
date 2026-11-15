// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! READING AN AuthnRequest (`saml2_sso.ts`'s `readAuthnRequest()`): what
//! saml-core-2.0-os section 3.4.1 puts on one, the attributes read as the
//! model marks them (#1579), and nothing refused: an attribute this service
//! does not act on is recorded so that the console can show what the
//! service provider sent.
//!
//! `signed` and `signing_certificate` are provisional, as in Node: whether
//! the request is signed and with what is the signature check's to say.
//!
//! ONE DIFFERENCE IN WORDS: a malformed message is refused with the parser's
//! own sentence after Node's prefix ("the AuthnRequest is not well-formed
//! XML: "), and that sentence is sts-xml's, not xmldom's.

use sts_xml::dom::{Document, NodeId};

use crate::model::{self, Read};

/// A read AuthnRequest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthnRequest {
    pub xml: String,
    pub id: String,
    pub version: String,
    pub issue_instant: String,
    pub destination: String,
    pub force_authn: bool,
    pub is_passive: bool,
    pub protocol_binding: String,
    pub acs_index: String,
    pub acs_url: String,
    /// Every other attribute the model marks `read`, by its model name.
    pub other: Vec<(String, String)>,
    pub issuer: String,
    pub name_id_format: String,
    pub allow_create: bool,
    pub subject_hint: String,
    pub subject_hint_format: String,
    pub requested_authn_contexts: Vec<String>,
    pub signed: bool,
    pub signing_certificate: String,
}

/// `firstByLocal()`: the first descendant with a local name, any
/// namespace.
fn first_by_local(doc: &Document, root: NodeId, local: &str) -> Option<NodeId> {
    doc.descendants(root)
        .into_iter()
        .skip(1)
        .find(|&n| doc.element(n).is_some_and(|e| e.local == local))
}

/// JavaScript's `String.prototype.trim()`.
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// `validation.parseXml(xml, what)`, as the SAML endpoints call it:
/// `Err(detail)` in Node's words for an empty or oversized document and
/// with the parser's own after them for a malformed one.
#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_xml(xml: &str, what: &str) -> Result<Document, String> {
    if js_trim(xml).is_empty() {
        return Err(format!(
            "the {} is empty. An empty body is not a document this service \
             can read anything out of.",
            what
        ));
    }
    let length = xml.encode_utf16().count();
    if length > crate::binding::INFLATE_MAX {
        return Err(format!(
            "the {} is {} characters and the limit is {}.",
            what,
            length,
            crate::binding::INFLATE_MAX
        ));
    }
    let doc = Document::parse(xml)
        .map_err(|e| format!("the {} is not well-formed XML: {}", what, e))?;
    if doc.document_element().is_none() {
        return Err(format!(
            "the {} parsed to nothing. It carries no root element.",
            what
        ));
    }
    Ok(doc)
}

/// `readAuthnRequest(xml)`: the request, or why it is not one.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_authn_request(xml: &str) -> Result<AuthnRequest, String> {
    let doc = parse_xml(xml, "AuthnRequest")?;
    let Some(root) = doc.document_element() else {
        return Err("the message is <nothing> and this endpoint reads \
                    <samlp:AuthnRequest>"
            .to_string());
    };
    let local = doc
        .element(root)
        .map(|e| e.local.clone())
        .unwrap_or_default();
    if local != "AuthnRequest" {
        return Err(format!(
            "the message is <{}> and this endpoint reads <samlp:AuthnRequest>",
            local
        ));
    }
    let mut out = AuthnRequest {
        xml: xml.to_string(),
        ..AuthnRequest::default()
    };
    for (name, value) in model::read("saml2.AuthnRequest", &doc, Some(root)) {
        match (name.as_str(), &value) {
            ("id", v) => out.id = v.text().to_string(),
            ("version", v) => out.version = v.text().to_string(),
            ("issueInstant", v) => out.issue_instant = v.text().to_string(),
            ("destination", v) => out.destination = v.text().to_string(),
            ("forceAuthn", v) => out.force_authn = v.truth(),
            ("isPassive", v) => out.is_passive = v.truth(),
            ("protocolBinding", v) => {
                out.protocol_binding = v.text().to_string()
            }
            ("acsIndex", v) => out.acs_index = v.text().to_string(),
            ("acsUrl", v) => out.acs_url = v.text().to_string(),
            (_, Read::Text(t)) => out.other.push((name.clone(), t.clone())),
            (_, Read::Bool(b)) => out.other.push((name.clone(), b.to_string())),
        }
    }
    if let Some(policy) = first_by_local(&doc, root, "NameIDPolicy") {
        for (name, value) in
            model::read("saml2.NameIDPolicy", &doc, Some(policy))
        {
            match name.as_str() {
                "nameIdFormat" => out.name_id_format = value.text().to_string(),
                "allowCreate" => out.allow_create = value.truth(),
                _ => {}
            }
        }
    }
    out.issuer = first_by_local(&doc, root, "Issuer")
        .map(|i| js_trim(&doc.text(i)).to_string())
        .unwrap_or_default();
    out.signed = first_by_local(&doc, root, "Signature").is_some();
    if let Some(subject) = first_by_local(&doc, root, "Subject") {
        if let Some(name_id) = first_by_local(&doc, subject, "NameID") {
            out.subject_hint = js_trim(&doc.text(name_id)).to_string();
            out.subject_hint_format = doc
                .element(name_id)
                .and_then(|e| e.attr("Format"))
                .unwrap_or("")
                .to_string();
        }
    }
    if let Some(requested) = first_by_local(&doc, root, "RequestedAuthnContext")
    {
        for n in doc.descendants(requested).into_iter().skip(1) {
            if doc
                .element(n)
                .is_some_and(|e| e.local == "AuthnContextClassRef")
            {
                out.requested_authn_contexts
                    .push(js_trim(&doc.text(n)).to_string());
            }
        }
    }
    Ok(out)
}
