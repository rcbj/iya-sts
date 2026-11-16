// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A SAML 2.0 ASSERTION'S ENVELOPED SIGNATURE, CHECKED HERE WHEN IT CAN BE
//! (#1760, D7) — and a question to the service whenever it cannot.
//!
//! **A LOCAL FAILURE IS NEVER A REFUSAL ON ITS OWN.** Everything here
//! answers [`Outcome::Verified`] or [`Outcome::CannotEstablish`], and the
//! second is `POST /xacml/pep/saml`'s to decide: an XML signature has more
//! legitimate shapes than this file reads, and refusing one this file does
//! not read would be refusing a person the service would admit. The one
//! local refusal is [`Outcome::Encrypted`]: neither end holds an SP's
//! decryption key.
//!
//! **WHAT IS READ IS ONE SHAPE, THE ONE THE SERVICE SIGNS** (`saml/saml2.ts`
//! through `common/crypto_impl/xmldsig.js`'s `signEnveloped()`): the
//! document is the Assertion; exactly one `ds:Signature` in it, a DIRECT
//! child of the Assertion; one Reference whose URI is `#` + the Assertion's
//! `ID`, and no other element carrying that id (signature wrapping); the
//! transforms exactly enveloped-signature then exclusive c14n, with no
//! InclusiveNamespaces; exclusive c14n for the SignedInfo; RSA PKCS#1 v1.5
//! or ECDSA with SHA-256/384/512; no `ds:Object`; no DOCTYPE, no processing
//! instruction. Anything else is a question for the service.
//!
//! **THE FACTS COME FROM THE VERIFIED ELEMENT AND NOTHING ELSE.** The
//! digest is over the Assertion node itself (minus its Signature), and the
//! Issuer, the Conditions, the audience and the NameID are read off that
//! same node's own children — never found by searching the document, which
//! is how a wrapped assertion is accepted elsewhere.
//!
//! **EXCLUSIVE C14N IS WRITTEN HERE** (W3C, *Exclusive XML Canonicalization
//! 1.0*, without comments), over roxmltree. roxmltree resolves namespaces
//! but does not keep the PREFIX an element or attribute was written with,
//! and c14n renders prefixes — so each is read from the source text at the
//! node's own range, never looked up by URI (two prefixes may name one
//! URI). Namespace declarations: only those visibly utilised by the
//! element's own name and attributes, and only when the nearest rendered
//! ancestor did not render the same binding; `xmlns=""` only to undo a
//! rendered default. Attributes sorted by namespace URI then local name,
//! the unqualified first; declarations sorted by prefix, the default
//! first; the escapes of section 2.3 of C14N 1.0; empty elements as start
//! and end tags; comments dropped.

use chrono::{DateTime, Utc};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::Id;
use openssl::sign::Verifier;
use openssl::x509::X509;
use roxmltree::{Document, Node, NodeId};

pub const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// The tolerance on the Conditions' instants, in seconds.
pub const SKEW_S: i64 = 60;

/// Who an assertion names.
#[derive(Debug, Clone, PartialEq)]
pub struct SamlIdentity {
    pub subject: String,
    pub username: Option<String>,
}

/// What the local check established.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// An EncryptedAssertion: refused, here and at the service.
    Encrypted,
    /// Signature, issuer, conditions and audience all hold.
    Verified(SamlIdentity),
    /// Not established here; the service is asked. The reason is for the
    /// log line, and names no value from the assertion.
    CannotEstablish(String),
}

fn cannot(why: &str) -> Outcome {
    Outcome::CannotEstablish(why.to_string())
}

/// The prefix an element was written with, read from the source.
fn element_prefix<'a>(source: &'a str, node: Node) -> Option<&'a str> {
    let start = node.range().start + 1;
    let rest = source.get(start..)?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(rest.len());
    rest[..end].split_once(':').map(|(p, _)| p)
}

/// The prefix an attribute was written with, read from the source.
fn attribute_prefix<'a>(
    source: &'a str,
    attribute: &roxmltree::Attribute,
) -> Option<&'a str> {
    source
        .get(attribute.range_qname())?
        .split_once(':')
        .map(|(p, _)| p)
}

fn escape_text(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

fn escape_attribute(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

/// The bindings rendered by the nearest output ancestor: prefix (empty for
/// the default) to URI.
type Rendered = Vec<(String, String)>;

fn rendered_uri<'r>(rendered: &'r Rendered, prefix: &str) -> Option<&'r str> {
    rendered
        .iter()
        .find(|(p, _)| p == prefix)
        .map(|(_, u)| u.as_str())
}

fn c14n_element(
    source: &str,
    node: Node,
    exclude: Option<NodeId>,
    inherited: &Rendered,
    out: &mut String,
) -> Result<(), String> {
    let prefix = element_prefix(source, node);
    let local = node.tag_name().name();
    let qname = match prefix {
        Some(p) => format!("{}:{}", p, local),
        None => local.to_string(),
    };
    // What this element's own name and attributes use.
    let mut used: Vec<(String, String)> = Vec::new();
    let element_uri = node.tag_name().namespace().unwrap_or("").to_string();
    if prefix.is_some() && element_uri.is_empty() {
        return Err("an element's prefix is bound to nothing".into());
    }
    used.push((prefix.unwrap_or("").to_string(), element_uri));
    let mut attributes: Vec<(String, String, String, String)> = Vec::new();
    for attribute in node.attributes() {
        let a_prefix = attribute_prefix(source, &attribute);
        let a_uri = attribute.namespace().unwrap_or("").to_string();
        let a_qname = match a_prefix {
            Some(p) => format!("{}:{}", p, attribute.name()),
            None => attribute.name().to_string(),
        };
        if let Some(p) = a_prefix {
            if a_uri.is_empty() {
                return Err("an attribute's prefix is bound to nothing".into());
            }
            if p != "xml" && !used.iter().any(|(u, _)| u == p) {
                used.push((p.to_string(), a_uri.clone()));
            }
        }
        attributes.push((
            a_uri,
            attribute.name().to_string(),
            a_qname,
            attribute.value().to_string(),
        ));
    }
    let mut declarations: Vec<(String, String)> = Vec::new();
    let mut rendered = inherited.clone();
    for (p, uri) in used {
        if p == "xml" {
            continue;
        }
        let current = rendered_uri(&rendered, &p);
        let render = if p.is_empty() {
            current.unwrap_or("") != uri
        } else {
            current != Some(uri.as_str())
        };
        if render {
            rendered.retain(|(q, _)| q != &p);
            rendered.push((p.clone(), uri.clone()));
            declarations.push((p, uri));
        }
    }
    declarations.sort_by(|a, b| a.0.cmp(&b.0));
    attributes.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    out.push('<');
    out.push_str(&qname);
    for (p, uri) in &declarations {
        if p.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(p);
            out.push_str("=\"");
        }
        escape_attribute(uri, out);
        out.push('"');
    }
    for (_, _, a_qname, value) in &attributes {
        out.push(' ');
        out.push_str(a_qname);
        out.push_str("=\"");
        escape_attribute(value, out);
        out.push('"');
    }
    out.push('>');
    for child in node.children() {
        if Some(child.id()) == exclude {
            continue;
        }
        if child.is_element() {
            c14n_element(source, child, exclude, &rendered, out)?;
        } else if child.is_text() {
            escape_text(child.text().unwrap_or(""), out);
        } else if child.is_pi() {
            return Err("a processing instruction".into());
        }
        // Comments are dropped: exclusive c14n WITHOUT comments.
    }
    out.push_str("</");
    out.push_str(&qname);
    out.push('>');
    Ok(())
}

/// Exclusive c14n (without comments) of `apex`, leaving `exclude` and its
/// subtree out — the enveloped-signature transform.
pub fn canonicalize(
    source: &str,
    apex: Node,
    exclude: Option<NodeId>,
) -> Result<String, String> {
    let mut out = String::new();
    c14n_element(source, apex, exclude, &Vec::new(), &mut out)?;
    Ok(out)
}

fn is(node: &Node, ns: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(ns)
        && node.tag_name().name() == name
}

fn element_children<'a, 'i>(node: Node<'a, 'i>) -> Vec<Node<'a, 'i>> {
    node.children().filter(Node::is_element).collect()
}

fn only_child<'a, 'i>(
    node: Node<'a, 'i>,
    ns: &str,
    name: &str,
) -> Option<Node<'a, 'i>> {
    let found: Vec<Node> = element_children(node)
        .into_iter()
        .filter(|c| is(c, ns, name))
        .collect();
    (found.len() == 1).then(|| found[0])
}

fn text_of(node: Node) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|t| t.text())
        .collect::<String>()
}

fn base64_of(node: Node) -> Option<Vec<u8>> {
    let text: String = text_of(node)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    openssl::base64::decode_block(&text).ok()
}

fn digest_for(uri: &str) -> Option<MessageDigest> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => {
            Some(MessageDigest::sha256())
        }
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => {
            Some(MessageDigest::sha384())
        }
        "http://www.w3.org/2001/04/xmlenc#sha512" => {
            Some(MessageDigest::sha512())
        }
        _ => None,
    }
}

/// (is ECDSA, digest) for a SignatureMethod this file verifies.
fn signature_method(uri: &str) -> Option<(bool, MessageDigest)> {
    let more = "http://www.w3.org/2001/04/xmldsig-more#";
    let name = uri.strip_prefix(more)?;
    match name {
        "rsa-sha256" => Some((false, MessageDigest::sha256())),
        "rsa-sha384" => Some((false, MessageDigest::sha384())),
        "rsa-sha512" => Some((false, MessageDigest::sha512())),
        "ecdsa-sha256" => Some((true, MessageDigest::sha256())),
        "ecdsa-sha384" => Some((true, MessageDigest::sha384())),
        "ecdsa-sha512" => Some((true, MessageDigest::sha512())),
        _ => None,
    }
}

fn verifies(
    certificate: &X509,
    ecdsa: bool,
    md: MessageDigest,
    data: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key) = certificate.public_key() else {
        return false;
    };
    let der;
    let sig: &[u8] = if ecdsa {
        if key.id() != Id::EC
            || signature.is_empty()
            || signature.len() % 2 != 0
        {
            return false;
        }
        let half = signature.len() / 2;
        let (Ok(r), Ok(s)) = (
            BigNum::from_slice(&signature[..half]),
            BigNum::from_slice(&signature[half..]),
        ) else {
            return false;
        };
        let Ok(bytes) = EcdsaSig::from_private_components(r, s)
            .and_then(|parsed| parsed.to_der())
        else {
            return false;
        };
        der = bytes;
        &der
    } else {
        if key.id() != Id::RSA {
            return false;
        }
        signature
    };
    let Ok(mut verifier) = Verifier::new(md, &key) else {
        return false;
    };
    verifier.verify_oneshot(sig, data).unwrap_or(false)
}

fn instant(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text.trim())
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn any_element_with_id(document: &Document, id: &str) -> usize {
    document
        .descendants()
        .filter(Node::is_element)
        .filter(|n| {
            n.attributes().any(|a| {
                matches!(a.name(), "ID" | "Id" | "id") && a.value() == id
            })
        })
        .count()
}

/// Checks one assertion here. `certificates` are the realm's signing
/// certificates as pulled; `now` is passed for the tests.
pub fn verify_local(
    xml: &str,
    certificates: &[X509],
    issuer: &str,
    audience: &str,
    now: DateTime<Utc>,
) -> Outcome {
    if xml.to_ascii_uppercase().contains("<!DOCTYPE") {
        return cannot("it carries a DOCTYPE");
    }
    let Ok(document) = Document::parse(xml) else {
        return cannot("it is not well-formed XML");
    };
    if document
        .descendants()
        .any(|n| is(&n, NS_SAML, "EncryptedAssertion"))
    {
        return Outcome::Encrypted;
    }
    let assertion = document.root_element();
    if !is(&assertion, NS_SAML, "Assertion") {
        return cannot("the document is not a SAML 2.0 Assertion");
    }
    if assertion.attribute("Version") != Some("2.0") {
        return cannot("its Version is not 2.0");
    }
    let Some(id) = assertion.attribute("ID").filter(|i| !i.is_empty()) else {
        return cannot("it has no ID");
    };
    if any_element_with_id(&document, id) != 1 {
        return cannot("another element carries the Assertion's ID");
    }
    if document
        .descendants()
        .filter(|n| is(n, NS_DS, "Signature"))
        .count()
        != 1
    {
        return cannot("it does not carry exactly one ds:Signature");
    }
    let Some(signature) = only_child(assertion, NS_DS, "Signature") else {
        return cannot("the ds:Signature is not a child of the Assertion");
    };
    if element_children(signature).iter().any(|c| {
        !(is(c, NS_DS, "SignedInfo")
            || is(c, NS_DS, "SignatureValue")
            || is(c, NS_DS, "KeyInfo"))
    }) {
        return cannot(
            "the ds:Signature carries something besides \
                       SignedInfo, SignatureValue and KeyInfo",
        );
    }
    let (Some(signed_info), Some(signature_value)) = (
        only_child(signature, NS_DS, "SignedInfo"),
        only_child(signature, NS_DS, "SignatureValue"),
    ) else {
        return cannot("it has no single SignedInfo and SignatureValue");
    };
    let parts = element_children(signed_info);
    if parts.len() != 3
        || !is(&parts[0], NS_DS, "CanonicalizationMethod")
        || !is(&parts[1], NS_DS, "SignatureMethod")
        || !is(&parts[2], NS_DS, "Reference")
    {
        return cannot(
            "its SignedInfo is not one method, one method and \
                       one Reference",
        );
    }
    if parts[0].attribute("Algorithm") != Some(EXC_C14N)
        || !element_children(parts[0]).is_empty()
    {
        return cannot(
            "its SignedInfo is not canonicalized by exclusive \
                       c14n without a prefix list",
        );
    }
    let Some((ecdsa, signature_md)) = parts[1]
        .attribute("Algorithm")
        .filter(|_| element_children(parts[1]).is_empty())
        .and_then(signature_method)
    else {
        return cannot("its SignatureMethod is not one verified here");
    };
    let reference = parts[2];
    if reference.attribute("URI") != Some(&format!("#{}", id)) {
        return cannot("its Reference does not name the Assertion's ID");
    }
    let reference_parts = element_children(reference);
    if reference_parts.len() != 3
        || !is(&reference_parts[0], NS_DS, "Transforms")
        || !is(&reference_parts[1], NS_DS, "DigestMethod")
        || !is(&reference_parts[2], NS_DS, "DigestValue")
    {
        return cannot(
            "its Reference is not Transforms, DigestMethod and \
                       DigestValue",
        );
    }
    let transforms = element_children(reference_parts[0]);
    let algorithms: Vec<Option<&str>> = transforms
        .iter()
        .map(|t| t.attribute("Algorithm"))
        .collect();
    if transforms.len() != 2
        || transforms.iter().any(|t| {
            !is(t, NS_DS, "Transform") || !element_children(*t).is_empty()
        })
        || algorithms != [Some(ENVELOPED), Some(EXC_C14N)]
    {
        return cannot(
            "its transforms are not exactly enveloped-signature \
                       and exclusive c14n",
        );
    }
    let Some(digest_md) = reference_parts[1]
        .attribute("Algorithm")
        .and_then(digest_for)
    else {
        return cannot("its DigestMethod is not one verified here");
    };
    let (Some(expected_digest), Some(signature_bytes)) =
        (base64_of(reference_parts[2]), base64_of(signature_value))
    else {
        return cannot("its DigestValue or SignatureValue is not base64");
    };
    // THE DIGEST, OVER THE ASSERTION NODE ITSELF, its Signature left out.
    let Ok(canonical) = canonicalize(xml, assertion, Some(signature.id()))
    else {
        return cannot("the Assertion could not be canonicalized here");
    };
    let Ok(digest) = hash(digest_md, canonical.as_bytes()) else {
        return cannot("the digest could not be computed");
    };
    if digest.len() != expected_digest.len()
        || !openssl::memcmp::eq(&digest, &expected_digest)
    {
        return cannot("the digest does not match");
    }
    let Ok(signed) = canonicalize(xml, signed_info, None) else {
        return cannot("the SignedInfo could not be canonicalized here");
    };
    if !certificates.iter().any(|c| {
        verifies(c, ecdsa, signature_md, signed.as_bytes(), &signature_bytes)
    }) {
        return cannot(
            "the signature does not verify against a pulled \
                       signing certificate",
        );
    }
    // FROM HERE ON, ONLY THE VERIFIED NODE'S OWN CHILDREN ARE READ.
    let named = only_child(assertion, NS_SAML, "Issuer").map(text_of);
    if issuer.is_empty() || named.as_deref().map(str::trim) != Some(issuer) {
        return cannot("its Issuer is not the realm's");
    }
    let Some(conditions) = only_child(assertion, NS_SAML, "Conditions") else {
        return cannot("it has no single Conditions");
    };
    let skew = chrono::Duration::seconds(SKEW_S);
    if let Some(before) = conditions.attribute("NotBefore") {
        match instant(before) {
            Some(at) if at - skew <= now => {}
            _ => return cannot("it is not valid yet (NotBefore)"),
        }
    }
    match conditions.attribute("NotOnOrAfter").and_then(instant) {
        Some(at) if now < at + skew => {}
        _ => return cannot("it has expired, or names no NotOnOrAfter"),
    }
    let restrictions = element_children(conditions);
    if restrictions.is_empty()
        || restrictions
            .iter()
            .any(|r| !is(r, NS_SAML, "AudienceRestriction"))
    {
        return cannot("its Conditions are not AudienceRestriction alone");
    }
    let addressed = restrictions.iter().all(|r| {
        element_children(*r).iter().any(|a| {
            is(a, NS_SAML, "Audience") && text_of(*a).trim() == audience
        })
    });
    if audience.is_empty() || !addressed {
        return cannot("it is not addressed to this route's audience");
    }
    let subject = only_child(assertion, NS_SAML, "Subject")
        .and_then(|s| only_child(s, NS_SAML, "NameID"))
        .map(|n| text_of(n).trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(subject) = subject else {
        return cannot("it names no subject (one NameID)");
    };
    let username = element_children(assertion)
        .into_iter()
        .filter(|s| is(s, NS_SAML, "AttributeStatement"))
        .flat_map(element_children)
        .filter(|a| {
            is(a, NS_SAML, "Attribute")
                && matches!(
                    a.attribute("Name"),
                    Some("uid") | Some("urn:oid:0.9.2342.19200300.100.1.1")
                )
        })
        .flat_map(element_children)
        .find(|v| is(v, NS_SAML, "AttributeValue"))
        .map(|v| text_of(v).trim().to_string())
        .filter(|u| !u.is_empty());
    Outcome::Verified(SamlIdentity { subject, username })
}

#[cfg(test)]
pub mod testing {
    //! An assertion in the service's shape, signed at run time with a key
    //! made at run time. Nothing here is key material in the tree.
    use super::*;
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use openssl::x509::{X509Builder, X509NameBuilder};

    pub fn signer() -> (PKey<Private>, X509) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "realm xml signer").unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(
            &Asn1Integer::from_bn(&BigNum::from_u32(9).unwrap()).unwrap(),
        )
        .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (key, b.build())
    }

    /// The assertion WITHOUT its signature, written so that its exclusive
    /// canonical form is known by hand: [`CANONICAL`] below is written out
    /// independently of `canonicalize()`, which the test holds to it.
    pub fn unsigned(not_on_or_after: &str, audience: &str) -> String {
        format!(
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
             xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" \
             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
             Version=\"2.0\" IssueInstant=\"2026-11-14T10:00:00Z\" ID=\"_a1\">\
             <saml:Issuer>https://sts.example/realm/r1</saml:Issuer>\
             <!-- a comment c14n drops -->\
             <saml:Subject><saml:NameID \
             Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">\
             urn:uuid:1234</saml:NameID></saml:Subject>\
             <saml:Conditions NotOnOrAfter=\"{}\" \
             NotBefore=\"2026-11-14T09:59:00Z\">\
             <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
             </saml:AudienceRestriction></saml:Conditions>\
             <saml:AttributeStatement><saml:Attribute Name=\"uid\">\
             <saml:AttributeValue xsi:type=\"xs:string\">alice &amp; co\
             </saml:AttributeValue></saml:Attribute></saml:AttributeStatement>\
             </saml:Assertion>",
            not_on_or_after, audience
        )
    }

    /// `unsigned("2026-11-14T10:05:00Z", "https://app.example/api")`, by
    /// hand: the `xs` declaration is gone (only a VALUE uses it), `xsi`
    /// moved to the one element whose attribute uses it, the attributes
    /// sorted (ID, IssueInstant, Version; Format; NotBefore, NotOnOrAfter),
    /// the comment dropped and `&` re-escaped.
    pub const CANONICAL: &str =
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
         ID=\"_a1\" IssueInstant=\"2026-11-14T10:00:00Z\" Version=\"2.0\">\
         <saml:Issuer>https://sts.example/realm/r1</saml:Issuer>\
         <saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">\
         urn:uuid:1234</saml:NameID></saml:Subject>\
         <saml:Conditions NotBefore=\"2026-11-14T09:59:00Z\" \
         NotOnOrAfter=\"2026-11-14T10:05:00Z\">\
         <saml:AudienceRestriction><saml:Audience>https://app.example/api\
         </saml:Audience></saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"uid\">\
         <saml:AttributeValue \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xsi:type=\"xs:string\">alice &amp; co</saml:AttributeValue>\
         </saml:Attribute></saml:AttributeStatement></saml:Assertion>";

    /// The SignedInfo's canonical form for a digest, by hand: the `ds`
    /// binding, declared on the Signature, rendered on the SignedInfo.
    pub fn canonical_signed_info(digest_b64: &str) -> String {
        format!(
            "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:CanonicalizationMethod \
             Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">\
             </ds:CanonicalizationMethod>\
             <ds:SignatureMethod \
             Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\">\
             </ds:SignatureMethod><ds:Reference URI=\"#_a1\"><ds:Transforms>\
             <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#\
             enveloped-signature\"></ds:Transform>\
             <ds:Transform Algorithm=\"http://www.w3.org/2001/10/\
             xml-exc-c14n#\"></ds:Transform></ds:Transforms>\
             <ds:DigestMethod \
             Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\">\
             </ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue>\
             </ds:Reference></ds:SignedInfo>",
            digest_b64
        )
    }

    /// Signs `xml` (an assertion from [`unsigned`]) as the service does:
    /// the Signature after the Issuer, the digest over `digest_input`
    /// (normally the canonical form; a test hands something else to forge
    /// a digest), the SignedInfo written with self-closing tags so its own
    /// canonicalization is exercised.
    pub fn sign(xml: &str, digest_input: &str, key: &PKey<Private>) -> String {
        let digest = openssl::base64::encode_block(
            &hash(MessageDigest::sha256(), digest_input.as_bytes()).unwrap(),
        );
        let canonical = canonical_signed_info(&digest);
        let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
        let value = openssl::base64::encode_block(
            &signer.sign_oneshot_to_vec(canonical.as_bytes()).unwrap(),
        );
        let signature = format!(
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:SignedInfo>\
             <ds:CanonicalizationMethod \
             Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
             <ds:SignatureMethod \
             Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\
             <ds:Reference URI=\"#_a1\"><ds:Transforms>\
             <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#\
             enveloped-signature\"/>\
             <ds:Transform Algorithm=\"http://www.w3.org/2001/10/\
             xml-exc-c14n#\"/></ds:Transforms>\
             <ds:DigestMethod \
             Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             <ds:DigestValue>{}</ds:DigestValue></ds:Reference>\
             </ds:SignedInfo><ds:SignatureValue>\n{}\n</ds:SignatureValue>\
             <ds:KeyInfo><ds:X509Data><ds:X509Certificate>ignored\
             </ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            digest, value
        );
        let at = xml.find("</saml:Issuer>").unwrap() + "</saml:Issuer>".len();
        format!("{}{}{}", &xml[..at], signature, &xml[at..])
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn now() -> DateTime<Utc> {
        instant("2026-11-14T10:01:00Z").unwrap()
    }

    const ISSUER: &str = "https://sts.example/realm/r1";
    const AUDIENCE: &str = "https://app.example/api";

    #[test]
    fn canonicalization_matches_the_form_written_by_hand() {
        let xml = unsigned("2026-11-14T10:05:00Z", AUDIENCE);
        let document = Document::parse(&xml).unwrap();
        let got = canonicalize(&xml, document.root_element(), None).unwrap();
        assert_eq!(got, CANONICAL);
        // A default namespace, an undeclaration and two prefixes for one
        // URI: each prefix is the one written, never a lookup by URI.
        let tricky = "<a xmlns=\"urn:x\" xmlns:p=\"urn:y\" xmlns:q=\"urn:y\">\
                      <b xmlns=\"\"><q:c p:k=\"1\" a=\"2\"/></b></a>";
        let document = Document::parse(tricky).unwrap();
        assert_eq!(
            canonicalize(tricky, document.root_element(), None).unwrap(),
            "<a xmlns=\"urn:x\"><b xmlns=\"\"><q:c xmlns:p=\"urn:y\" \
             xmlns:q=\"urn:y\" a=\"2\" p:k=\"1\"></q:c></b></a>"
        );
    }

    #[test]
    fn a_signed_assertion_verifies_here() {
        let (key, certificate) = signer();
        let xml = unsigned("2026-11-14T10:05:00Z", AUDIENCE);
        let signed = sign(&xml, CANONICAL, &key);
        assert_eq!(
            verify_local(&signed, &[certificate], ISSUER, AUDIENCE, now()),
            Outcome::Verified(SamlIdentity {
                subject: "urn:uuid:1234".into(),
                username: Some("alice & co".into()),
            })
        );
    }

    #[test]
    fn every_local_failure_is_a_question_for_the_service() {
        let (key, certificate) = signer();
        let (_, stranger) = signer();
        let certs = std::slice::from_ref(&certificate);
        let xml = unsigned("2026-11-14T10:05:00Z", AUDIENCE);
        let good = sign(&xml, CANONICAL, &key);
        let asks = |doc: &str, certs: &[X509], why: &str| match verify_local(
            doc,
            certs,
            ISSUER,
            AUDIENCE,
            now(),
        ) {
            Outcome::CannotEstablish(reason) => {
                assert!(reason.contains(why), "{} lacks {}", reason, why)
            }
            other => panic!("{:?} for {}", other, why),
        };
        asks(&good, &[stranger], "does not verify");
        // A digest over other bytes than the element's (a forged digest).
        asks(&sign(&xml, "something else", &key), certs, "digest");
        // The content changed after signing.
        asks(
            &good.replace("urn:uuid:1234", "urn:uuid:9999"),
            certs,
            "digest",
        );
        asks(&good.replace("#_a1", "#_other"), certs, "Reference");
        asks(
            &good.replace("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1"),
            certs,
            "SignatureMethod",
        );
        asks(
            &good.replace(
                "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#\
                 enveloped-signature\"/>",
                "",
            ),
            certs,
            "transforms",
        );
        asks(&format!("<!DOCTYPE x []>{}", good), certs, "DOCTYPE");
        // Signature wrapping: a second element carrying the signed ID.
        asks(
            &good.replace(
                "<saml:Subject>",
                "<saml:Advice ID=\"_a1\"/><saml:Subject>",
            ),
            certs,
            "ID",
        );
        // Signed correctly, but not for this audience / issuer / time.
        let elsewhere = unsigned("2026-11-14T10:05:00Z", "https://other");
        let elsewhere_c = CANONICAL.replace(AUDIENCE, "https://other");
        let elsewhere = sign(&elsewhere, &elsewhere_c, &key);
        asks(&elsewhere, certs, "audience");
        let late = unsigned("2026-11-14T09:58:00Z", AUDIENCE);
        let late_c =
            CANONICAL.replace("2026-11-14T10:05:00Z", "2026-11-14T09:58:00Z");
        asks(&sign(&late, &late_c, &key), certs, "expired");
        match verify_local(&good, certs, "https://other", AUDIENCE, now()) {
            Outcome::CannotEstablish(r) => assert!(r.contains("Issuer")),
            other => panic!("{:?}", other),
        }
        assert_eq!(
            verify_local(
                "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:\
                 SAML:2.0:assertion\"/>",
                certs,
                ISSUER,
                AUDIENCE,
                now()
            ),
            Outcome::Encrypted
        );
        asks("not xml", certs, "well-formed");
    }
}
