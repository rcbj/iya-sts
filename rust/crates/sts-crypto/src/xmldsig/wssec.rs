// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE WS-SECURITY MESSAGE SIGNATURE (#521, #658): `common/crypto.js`'s
//! `readWsSecuritySignature()`, `verifyWsSecuritySignature()` and
//! `verifyWsSecurityHmac()`, and the vendored engine's `signWsSecurity()`
//! that the test side signs requests with.
//!
//! A WS-Trust request whose `wsse:Security` header carries one
//! `ds:Signature` over the SOAP Body and the `wsu:Timestamp` names its
//! signer. The READING applies every structural guard against signature
//! wrapping, in Node's order and words: one signature, every id in the
//! document unique, exclusive canonicalization only (WS-I BSP R5404,
//! R5412), every Reference a same-document `#id`, the Body and the
//! Timestamp covered BY POSITION, the algorithms through the realm's policy
//! (an HMAC only where the KeyInfo names a Kerberos token), and the key
//! reference in one of the X.509 Token Profile's four forms or the Kerberos
//! Token Profile's two. Who the certificate is, its revocation and the
//! message's freshness are the caller's questions (`ws-trust/wstrust.ts`).
//!
//! **THE VERIFICATION IS NODE'S, ON A SERIALIZED COPY, AND ON PURPOSE.**
//! `xmldsig.rs`'s [`verify_xml_signature`] canonicalizes in place, a
//! deliberate fix its module comment states. This surface does NOT: Node
//! hands the vendored engine the `ds:Signature` serialized on its own (with
//! the certificate text emptied, `withoutCertificateText()`) and the whole
//! envelope to resolve the References in, and xmldom's serializer declares
//! only the prefixes the copy's elements and attributes USE. So a prefix an
//! exclusive `InclusiveNamespaces PrefixList` on the CanonicalizationMethod
//! names and an ancestor declares is not in the SignedInfo's octets, and
//! such a signature is refused here as it is in Node (STS-KEYS-0012). The
//! verdicts, refusals included, must be the same in both runtimes, because
//! a WS-Trust requester that one accepts and the other refuses is a
//! requester whose authentication changed at the upgrade.
//! [`serialize_detached`] is xmldom's `XMLSerializer` over one subtree; the
//! copy is then parsed again and verified as the engine verifies it.

use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use sts_xml::dom::{Document, NodeId, NodeKind, XMLNS_NS, XML_NS};

use super::*;

/// The WS-Security 1.0 secext namespace.
pub const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/\
     oasis-200401-wss-wssecurity-secext-1.0.xsd";
/// The WS-Security 1.0 utility namespace (`wsu:Id`, `wsu:Timestamp`).
pub const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/\
     oasis-200401-wss-wssecurity-utility-1.0.xsd";

const KERBEROS_PREFIX: &str = "http://docs.oasis-open.org/wss/\
     oasis-wss-kerberos-token-profile-1.1#";

/// What the signature's KeyInfo names, in the forms `keyReferenceOf()`
/// reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyReference {
    /// A `wsse:BinarySecurityToken` (#X509v3) by reference.
    Token { id: String, cert_b64: String },
    /// A Kerberos token by reference (#658), whose session key signs.
    Kerberos {
        id: String,
        value_type: String,
        token_b64: String,
    },
    /// The Kerberos Token Profile's own key identifier (#Kerberosv5APREQSHA1).
    KerberosId { key_identifier: String },
    /// The certificate's SHA-1 thumbprint, lowercase hex.
    Thumbprint { sha1: String },
    /// Its Subject Key Identifier, lowercase hex.
    Ski { ski: String },
    /// Its issuer and serial (the serial in lowercase hex, as
    /// `BigInt(serial).toString(16)` writes it).
    IssuerSerial { issuer: String, serial_hex: String },
}

impl KeyReference {
    /// Node's `kind`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn kind(&self) -> &'static str {
        match self {
            KeyReference::Token { .. } => "token",
            KeyReference::Kerberos { .. } => "kerberos",
            KeyReference::KerberosId { .. } => "kerberos-id",
            KeyReference::Thumbprint { .. } => "thumbprint",
            KeyReference::Ski { .. } => "ski",
            KeyReference::IssuerSerial { .. } => "issuer-serial",
        }
    }

    fn shared_key(&self) -> bool {
        matches!(
            self,
            KeyReference::Kerberos { .. } | KeyReference::KerberosId { .. }
        )
    }
}

/// The Timestamp's two instants, as written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsTimestamp {
    pub created: String,
    pub expires: String,
}

/// `readWsSecuritySignature()`'s answer, and the verifiers' (which add
/// `signature_valid`, `references_valid` and `signer_subject`). A field is
/// `None` where Node's object carries no such key, so the two can be
/// compared key for key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsSecurityReading {
    pub present: bool,
    pub ok: bool,
    pub why: String,
    pub code: Option<ErrorCode>,
    pub key_reference: Option<KeyReference>,
    pub timestamp: Option<WsTimestamp>,
    pub signature_value: Option<String>,
    pub references: Option<Vec<String>>,
    pub signature_method: Option<String>,
    pub digest_methods: Option<Vec<String>>,
    pub weak: Option<bool>,
    pub sha1: Option<bool>,
    pub signature_valid: Option<bool>,
    pub references_valid: Option<bool>,
    pub signer_subject: Option<String>,
}

impl WsSecurityReading {
    fn absent() -> WsSecurityReading {
        WsSecurityReading::default()
    }

    fn refused(code: ErrorCode, why: String) -> WsSecurityReading {
        WsSecurityReading {
            present: true,
            why,
            code: Some(code),
            ..WsSecurityReading::default()
        }
    }

    /// The reading, now refused: `Object.assign({}, reading, { ok: false,
    /// why })` marked with `code`.
    fn now_refused(&self, code: ErrorCode, why: String) -> WsSecurityReading {
        WsSecurityReading {
            ok: false,
            why,
            code: Some(code),
            ..self.clone()
        }
    }
}

/// `wsuIdOf()`: `wsu:Id` first, then `idOf()`'s six spellings.
fn wsu_id_of(doc: &Document, el: NodeId) -> String {
    let wsu = doc
        .element(el)
        .and_then(|e| {
            e.attrs
                .iter()
                .find(|a| a.local == "Id" && a.ns.as_deref() == Some(WSU_NS))
        })
        .map(|a| a.value.clone())
        .unwrap_or_default();
    if wsu.is_empty() {
        id_of(doc, el)
    } else {
        wsu
    }
}

/// `duplicateIdsOf()`: every id-like value carried more than once, in the
/// order each is first seen repeated.
fn duplicate_ids_of(doc: &Document) -> Vec<String> {
    const ID_ATTRIBUTES: [&str; 6] =
        ["ID", "AssertionID", "ResponseID", "RequestID", "Id", "id"];
    let mut seen: Vec<String> = Vec::new();
    let mut twice: Vec<String> = Vec::new();
    for n in doc.descendants(Document::ROOT) {
        let Some(e) = doc.element(n) else {
            continue;
        };
        for a in &e.attrs {
            if !ID_ATTRIBUTES.contains(&a.local.as_str()) {
                continue;
            }
            if seen.contains(&a.value) {
                if !twice.contains(&a.value) {
                    twice.push(a.value.clone());
                }
            } else {
                seen.push(a.value.clone());
            }
        }
    }
    twice
}

/// `directChildrenByLocal()`, in any namespace.
fn children_by_local(
    doc: &Document,
    parent: Option<NodeId>,
    local: &str,
) -> Vec<NodeId> {
    let Some(parent) = parent else {
        return Vec::new();
    };
    doc.child_elements(parent)
        .into_iter()
        .filter(|&c| doc.element(c).is_some_and(|e| e.local == local))
        .collect()
}

fn child(
    doc: &Document,
    parent: Option<NodeId>,
    local: &str,
    ns: Option<&str>,
) -> Option<NodeId> {
    parent.and_then(|p| direct_child(doc, p, local, ns))
}

/// JavaScript's `\s`.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{b}'
            | '\u{c}'
            | '\r'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `.replace(/\s+/g, '')`.
fn strip_js_ws(s: &str) -> String {
    s.chars().filter(|&c| !js_space(c)).collect()
}

/// `String.prototype.trim()`.
fn js_trim(s: &str) -> &str {
    s.trim_matches(js_space)
}

/// `Buffer.from(text, 'base64')`: both alphabets, anything else skipped,
/// the end at the first `=`.
fn node_base64(text: &str) -> Vec<u8> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        bits = (bits << 6) | v;
        count += 1;
        if count == 4 {
            out.push((bits >> 16) as u8);
            out.push((bits >> 8) as u8);
            out.push(bits as u8);
            bits = 0;
            count = 0;
        }
    }
    match count {
        2 => out.push((bits >> 4) as u8),
        3 => {
            out.push((bits >> 10) as u8);
            out.push((bits >> 2) as u8);
        }
        _ => {}
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// `BigInt(decimal).toString(16)`, for a string of ASCII digits.
fn decimal_to_hex(decimal: &str) -> String {
    // Little-endian base-2^32 limbs, multiplied up digit by digit.
    let mut limbs: Vec<u64> = vec![0];
    for d in decimal.bytes() {
        let mut carry = u64::from(d - b'0');
        for limb in limbs.iter_mut() {
            let v = *limb * 10 + carry;
            *limb = v & 0xffff_ffff;
            carry = v >> 32;
        }
        if carry > 0 {
            limbs.push(carry);
        }
    }
    let mut s = String::new();
    for (i, limb) in limbs.iter().rev().enumerate() {
        if i == 0 {
            s.push_str(&format!("{:x}", limb));
        } else {
            s.push_str(&format!("{:08x}", limb));
        }
    }
    s
}

/// `keyReferenceOf()`: the key the signature's KeyInfo names, or the
/// sentence that says why it names none this service reads.
fn key_reference_of(
    doc: &Document,
    sig: NodeId,
    security: NodeId,
) -> Result<KeyReference, String> {
    let key_info = child(doc, Some(sig), "KeyInfo", None);
    let Some(str_el) = child(doc, key_info, "SecurityTokenReference", None)
    else {
        return Err("the signature's KeyInfo holds no \
                    wsse:SecurityTokenReference, so it names no X.509 \
                    certificate in a form the X.509 Token Profile 1.1 \
                    gives a requester"
            .to_string());
    };
    if let Some(reference) = child(doc, Some(str_el), "Reference", None) {
        let uri = attr(doc, reference, "URI").to_string();
        let id = uri.strip_prefix('#').unwrap_or("").to_string();
        let tokens: Vec<NodeId> =
            children_by_local(doc, Some(security), "BinarySecurityToken")
                .into_iter()
                .filter(|&t| !id.is_empty() && wsu_id_of(doc, t) == id)
                .collect();
        if tokens.len() != 1 {
            return Err(format!(
                "the SecurityTokenReference points at \"{}\", which is not \
                 a wsse:BinarySecurityToken in this security header",
                uri
            ));
        }
        let value_type = attr(doc, tokens[0], "ValueType").to_string();
        if is_kerberos_token_type(&value_type) {
            return Ok(KeyReference::Kerberos {
                id,
                value_type,
                token_b64: strip_js_ws(&doc.text(tokens[0])),
            });
        }
        if !value_type.ends_with("#X509v3") {
            return Err(format!(
                "the referenced wsse:BinarySecurityToken is a \"{}\", not \
                 an X.509 v3 certificate (#X509v3)",
                value_type
            ));
        }
        return Ok(KeyReference::Token {
            id,
            cert_b64: strip_js_ws(&doc.text(tokens[0])),
        });
    }
    if let Some(ki) = child(doc, Some(str_el), "KeyIdentifier", None) {
        let value_type = attr(doc, ki, "ValueType").to_string();
        let encoding = attr(doc, ki, "EncodingType");
        let text = strip_js_ws(&doc.text(ki));
        let hexed = if encoding.ends_with("#HexBinary") {
            text.to_lowercase()
        } else {
            hex(&node_base64(&text))
        };
        if value_type.ends_with("#Kerberosv5APREQSHA1") && !text.is_empty() {
            return Ok(KeyReference::KerberosId {
                key_identifier: text,
            });
        }
        if value_type.ends_with("#ThumbprintSHA1") && hexed.len() == 40 {
            return Ok(KeyReference::Thumbprint { sha1: hexed });
        }
        if value_type.ends_with("#X509SubjectKeyIdentifier")
            && !hexed.is_empty()
        {
            return Ok(KeyReference::Ski { ski: hexed });
        }
        return Err(format!(
            "the KeyIdentifier is a \"{}\", which is not a SHA-1 thumbprint \
             (#ThumbprintSHA1) or a Subject Key Identifier \
             (#X509SubjectKeyIdentifier) this service reads",
            value_type
        ));
    }
    let data = child(doc, Some(str_el), "X509Data", None);
    if let Some(is) = child(doc, data, "X509IssuerSerial", None) {
        let issuer = child(doc, Some(is), "X509IssuerName", None);
        let serial = child(doc, Some(is), "X509SerialNumber", None)
            .map(|s| js_trim(&doc.text(s)).to_string())
            .unwrap_or_default();
        if let Some(issuer) = issuer {
            if !serial.is_empty() && serial.bytes().all(|b| b.is_ascii_digit())
            {
                return Ok(KeyReference::IssuerSerial {
                    issuer: js_trim(&doc.text(issuer)).to_string(),
                    serial_hex: decimal_to_hex(&serial),
                });
            }
        }
    }
    Err(
        "the SecurityTokenReference names its certificate in no form this \
         service reads: a Reference to a BinarySecurityToken, a \
         KeyIdentifier (#ThumbprintSHA1 or #X509SubjectKeyIdentifier) or an \
         X509IssuerSerial"
            .to_string(),
    )
}

/// `KERBEROS_TOKEN_TYPE`: the Kerberos Token Profile 1.1's six ValueTypes.
fn is_kerberos_token_type(value_type: &str) -> bool {
    let Some(rest) = value_type.strip_prefix(KERBEROS_PREFIX) else {
        return false;
    };
    let rest = rest.strip_prefix("GSS_").unwrap_or(rest);
    matches!(
        rest,
        "Kerberosv5_AP_REQ" | "Kerberosv5_AP_REQ1510" | "Kerberosv5_AP_REQ4120"
    )
}

/// The parts of an envelope the reading and the verifiers each locate.
struct Located {
    doc: Document,
    security: Option<NodeId>,
    signatures: Vec<NodeId>,
}

fn locate(xml: &str) -> Option<Located> {
    let doc = Document::parse(xml).ok()?;
    let envelope = doc.document_element();
    let header = child(&doc, envelope, "Header", None);
    let securities = children_by_local(&doc, header, "Security");
    let security = (securities.len() == 1).then(|| securities[0]);
    let signatures: Vec<NodeId> =
        children_by_local(&doc, security, "Signature")
            .into_iter()
            .filter(|&s| {
                doc.element(s)
                    .is_some_and(|e| e.ns.as_deref() == Some(DS_NS))
            })
            .collect();
    Some(Located {
        doc,
        security,
        signatures,
    })
}

/// `crypto.readWsSecuritySignature()`: the message signature in a SOAP
/// envelope, read and guarded but not verified. It answers rather than
/// panics; `present` is false when the security header carries none.
#[tracing::instrument(skip_all)]
pub fn read_ws_security_signature(
    xml: &str,
    policy: &XmlPolicy,
) -> WsSecurityReading {
    let Some(located) = locate(xml) else {
        return WsSecurityReading::absent();
    };
    let Located {
        doc,
        security,
        signatures,
    } = located;
    let Some(security) = security else {
        return WsSecurityReading::absent();
    };
    if signatures.is_empty() {
        return WsSecurityReading::absent();
    }
    if signatures.len() > 1 {
        return WsSecurityReading::refused(
            codes::STS_KEYS_0159,
            "the security header carries more than one ds:Signature, so it \
             does not say which one the requester made"
                .to_string(),
        );
    }
    let sig = signatures[0];
    let repeated = duplicate_ids_of(&doc);
    if !repeated.is_empty() {
        let named = if repeated.len() == 1 {
            format!(" \"{}\" is", repeated[0])
        } else {
            format!("s \"{}\" are", repeated.join("\", \""))
        };
        return WsSecurityReading::refused(
            codes::STS_KEYS_0160,
            format!(
                "the id{} carried by more than one element, so a Reference \
                 to it does not say which element was signed",
                named
            ),
        );
    }
    // A ds:Signature with no SignedInfo signs nothing and is read as none:
    // WS-Trust's `?encrypt=1` test control carries a bare KeyInfo there.
    let Some(signed_info) = child(&doc, Some(sig), "SignedInfo", Some(DS_NS))
    else {
        return WsSecurityReading::absent();
    };
    let c14n_el = child(
        &doc,
        Some(signed_info),
        "CanonicalizationMethod",
        Some(DS_NS),
    );
    let method_el =
        child(&doc, Some(signed_info), "SignatureMethod", Some(DS_NS));
    let value_el = child(&doc, Some(sig), "SignatureValue", Some(DS_NS));
    let (Some(method_el), Some(value_el)) = (method_el, value_el) else {
        return WsSecurityReading::refused(
            codes::STS_KEYS_0161,
            "the ds:Signature has no SignatureMethod or SignatureValue"
                .to_string(),
        );
    };
    let c14n = c14n_el
        .map(|c| attr(&doc, c, "Algorithm").to_string())
        .unwrap_or_default();
    let signature_method = attr(&doc, method_el, "Algorithm").to_string();
    let mut uris: Vec<String> = Vec::new();
    let mut digest_methods: Vec<String> = Vec::new();
    for r in children_by_local(&doc, Some(signed_info), "Reference") {
        let uri = attr(&doc, r, "URI").to_string();
        let transforms = child(&doc, Some(r), "Transforms", Some(DS_NS));
        // `String(one.getAttribute('Algorithm'))`: an absent one is "null".
        let each: Vec<String> =
            children_by_local(&doc, transforms, "Transform")
                .into_iter()
                .map(|t| {
                    doc.element(t)
                        .and_then(|e| e.attr("Algorithm"))
                        .map(str::to_string)
                        .unwrap_or_else(|| "null".to_string())
                })
                .collect();
        digest_methods.push(
            child(&doc, Some(r), "DigestMethod", Some(DS_NS))
                .map(|d| attr(&doc, d, "Algorithm").to_string())
                .unwrap_or_default(),
        );
        if !uri.starts_with('#') || uri.len() < 2 {
            return WsSecurityReading::refused(
                codes::STS_KEYS_0161,
                format!(
                    "the Reference \"{}\" is not a same-document reference \
                     by id; a WS-Security signature names each part it \
                     covers by its wsu:Id",
                    uri
                ),
            );
        }
        if each.len() != 1 || each[0] != C14N_EXCLUSIVE {
            let named = if each.is_empty() {
                "nothing".to_string()
            } else {
                each.join(", ")
            };
            return WsSecurityReading::refused(
                codes::STS_KEYS_0162,
                format!(
                    "the Reference \"{}\" is transformed by {}; a part is \
                     signed here only under exclusive XML canonicalization \
                     ({}), as the Basic Security Profile requires",
                    uri, named, C14N_EXCLUSIVE
                ),
            );
        }
        uris.push(uri[1..].to_string());
    }
    if c14n != C14N_EXCLUSIVE {
        return WsSecurityReading::refused(
            codes::STS_KEYS_0162,
            format!(
                "the SignedInfo is canonicalized with \"{}\"; only exclusive \
                 XML canonicalization ({}) is accepted for a WS-Security \
                 signature",
                c14n, C14N_EXCLUSIVE
            ),
        );
    }
    let envelope = doc.document_element();
    let bodies = children_by_local(&doc, envelope, "Body");
    let timestamps = children_by_local(&doc, Some(security), "Timestamp");
    let body = (bodies.len() == 1).then(|| bodies[0]);
    let timestamp = (timestamps.len() == 1).then(|| timestamps[0]);
    let body_id = body.map(|b| wsu_id_of(&doc, b)).unwrap_or_default();
    let timestamp_id =
        timestamp.map(|t| wsu_id_of(&doc, t)).unwrap_or_default();
    let mut missing = Vec::new();
    if body_id.is_empty() || !uris.contains(&body_id) {
        missing.push("the SOAP Body");
    }
    if timestamp_id.is_empty() || !uris.contains(&timestamp_id) {
        missing.push("the wsu:Timestamp in this security header");
    }
    if !missing.is_empty() {
        let referenced = if uris.is_empty() {
            "nothing".to_string()
        } else {
            uris.iter()
                .map(|u| format!("#{}", u))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return WsSecurityReading::refused(
            codes::STS_KEYS_0163,
            format!(
                "the signature does not cover {} by its wsu:Id — what it \
                 references ({}) is not the element this service acts on, \
                 which is the signature-wrapping shape",
                missing.join(" or "),
                referenced
            ),
        );
    }
    // #658: an HMAC is checkable only when the KeyInfo names a Kerberos
    // token; the reference is read here for that one fact, and its refusal
    // is still made below, in the order Node makes it.
    let named = key_reference_of(&doc, sig, security);
    let shared = named.as_ref().is_ok_and(KeyReference::shared_key);
    let algorithms = algorithm_verdict_keyed(
        &signature_method,
        &digest_methods,
        policy,
        shared,
    );
    if !algorithms.problem.is_empty() {
        let mut r = WsSecurityReading::refused(
            algorithms.code.unwrap_or(codes::STS_KEYS_0061),
            algorithms.problem.clone(),
        );
        r.signature_method = Some(signature_method);
        r.digest_methods = Some(digest_methods);
        r.weak = Some(algorithms.weak);
        r.sha1 = Some(algorithms.sha1);
        return r;
    }
    let key_reference = match named {
        Ok(k) => k,
        Err(problem) => {
            return WsSecurityReading::refused(codes::STS_KEYS_0164, problem)
        }
    };
    let instant = |local: &str| {
        child(&doc, timestamp, local, None)
            .map(|e| js_trim(&doc.text(e)).to_string())
            .unwrap_or_default()
    };
    WsSecurityReading {
        present: true,
        ok: true,
        why: String::new(),
        code: None,
        key_reference: Some(key_reference),
        timestamp: Some(WsTimestamp {
            created: instant("Created"),
            expires: instant("Expires"),
        }),
        signature_value: Some(strip_js_ws(&doc.text(value_el))),
        references: Some(uris.iter().map(|u| format!("#{}", u)).collect()),
        signature_method: Some(signature_method),
        digest_methods: Some(digest_methods),
        weak: Some(algorithms.weak),
        sha1: Some(algorithms.sha1),
        signature_valid: None,
        references_valid: None,
        signer_subject: None,
    }
}

// ---------------------------------------------------------------------------
// xmldom's XMLSerializer over one subtree.
// ---------------------------------------------------------------------------

/// One entry of xmldom's `visibleNamespaces`.
#[derive(Clone)]
struct Visible {
    prefix: String,
    ns: String,
}

/// `needNamespaceDefine()`.
fn need_define(prefix: &str, ns: Option<&str>, visible: &[Visible]) -> bool {
    let Some(ns) = ns.filter(|n| !n.is_empty()) else {
        return false;
    };
    if (prefix == "xml" && ns == XML_NS) || ns == XMLNS_NS {
        return false;
    }
    for v in visible.iter().rev() {
        if v.prefix == prefix {
            return v.ns != ns;
        }
    }
    true
}

fn attribute(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!(
        " {}=\"{}\"",
        name,
        sts_xml::dom::escape_attr(value)
    ));
}

/// `new XMLSerializer().serializeToString(node)` for an element of a parsed
/// document: the subtree as written, with a declaration added wherever an
/// element or an attribute uses a prefix (or the default namespace) the
/// copy does not declare — and nothing else an ancestor declared.
#[tracing::instrument(level = "debug", skip_all)]
pub fn serialize_detached(doc: &Document, node: NodeId) -> String {
    let mut out = String::new();
    write_detached(doc, node, &[], &mut out);
    out
}

fn write_detached(
    doc: &Document,
    node: NodeId,
    visible: &[Visible],
    out: &mut String,
) {
    match doc.kind(node) {
        NodeKind::Element(e) => {
            let node_name = e.name();
            let mut prefixed = node_name.clone();
            if e.prefix.is_none() && e.ns.is_some() {
                let own_default = e
                    .attrs
                    .iter()
                    .find(|a| a.prefix.is_none() && a.local == "xmlns")
                    .map(|a| a.value.clone());
                let default_ns = own_default.or_else(|| {
                    visible
                        .iter()
                        .rev()
                        .find(|v| {
                            v.prefix.is_empty()
                                && Some(v.ns.as_str()) == e.ns.as_deref()
                        })
                        .map(|v| v.ns.clone())
                });
                if default_ns.as_deref() != e.ns.as_deref() {
                    if let Some(v) = visible
                        .iter()
                        .rev()
                        .find(|v| Some(v.ns.as_str()) == e.ns.as_deref())
                    {
                        if !v.prefix.is_empty() {
                            prefixed = format!("{}:{}", v.prefix, node_name);
                        }
                    }
                }
            }
            out.push('<');
            out.push_str(&prefixed);
            let mut scope: Vec<Visible> = visible.to_vec();
            for a in &e.attrs {
                if a.prefix.as_deref() == Some("xmlns") {
                    scope.push(Visible {
                        prefix: a.local.clone(),
                        ns: a.value.clone(),
                    });
                } else if a.prefix.is_none() && a.local == "xmlns" {
                    scope.push(Visible {
                        prefix: String::new(),
                        ns: a.value.clone(),
                    });
                }
            }
            for a in &e.attrs {
                let p = a.prefix.clone().unwrap_or_default();
                if need_define(&p, a.ns.as_deref(), &scope) {
                    let ns = a.ns.clone().unwrap_or_default();
                    let decl = if p.is_empty() {
                        "xmlns".to_string()
                    } else {
                        format!("xmlns:{}", p)
                    };
                    attribute(out, &decl, &ns);
                    scope.push(Visible { prefix: p, ns });
                }
                attribute(out, &a.name(), &a.value);
            }
            let p = e.prefix.clone().unwrap_or_default();
            if node_name == prefixed && need_define(&p, e.ns.as_deref(), &scope)
            {
                let ns = e.ns.clone().unwrap_or_default();
                let decl = if p.is_empty() {
                    "xmlns".to_string()
                } else {
                    format!("xmlns:{}", p)
                };
                attribute(out, &decl, &ns);
                scope.push(Visible { prefix: p, ns });
            }
            let children = doc.children(node);
            if children.is_empty() {
                out.push_str("/>");
                return;
            }
            out.push('>');
            for &c in children {
                write_detached(doc, c, &scope, out);
            }
            out.push_str(&format!("</{}>", prefixed));
        }
        _ => out.push_str(&doc.serialize_node(node)),
    }
}

/// `withoutCertificateText()`: every `X509Certificate` element's text
/// emptied, as the pattern
/// `/(<(?:[A-Za-z_][\w.-]*:)?X509Certificate\b[^>]*>)[^<]*(<\/)/g` does.
#[tracing::instrument(level = "debug", skip_all)]
pub fn without_certificate_text(xml: &str) -> String {
    let b = xml.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = String::with_capacity(xml.len());
    let mut i = 0;
    let mut copied = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        // The tag: an optional prefix, then the name, then a word boundary.
        let mut j = i + 1;
        let try_name = |at: usize| -> Option<usize> {
            let name = b"X509Certificate";
            let end = at + name.len();
            (b.get(at..end) == Some(&name[..])
                && !b.get(end).is_some_and(|&c| word(c)))
            .then_some(end)
        };
        let mut name_end = try_name(j);
        if name_end.is_none()
            && b.get(j)
                .is_some_and(|&c| c.is_ascii_alphabetic() || c == b'_')
        {
            j += 1;
            while b.get(j).is_some_and(|&c| word(c) || c == b'.' || c == b'-') {
                j += 1;
            }
            // `[\w.-]*` backtracks to the last colon it can stop before.
            let mut k = j;
            while k > i + 1 {
                if b.get(k) == Some(&b':') {
                    if let Some(end) = try_name(k + 1) {
                        name_end = Some(end);
                        break;
                    }
                }
                k -= 1;
            }
        }
        let Some(mut k) = name_end else {
            i += 1;
            continue;
        };
        while k < b.len() && b[k] != b'>' {
            k += 1;
        }
        if k >= b.len() {
            i += 1;
            continue;
        }
        let open_end = k + 1;
        let mut t = open_end;
        while t < b.len() && b[t] != b'<' {
            t += 1;
        }
        if b.get(t..t + 2) != Some(b"</") {
            i += 1;
            continue;
        }
        out.push_str(&xml[copied..open_end]);
        copied = t;
        i = t;
    }
    out.push_str(&xml[copied..]);
    out
}

// ---------------------------------------------------------------------------
// The engine, on the copy.
// ---------------------------------------------------------------------------

/// What `xmldsig.verifyXml()` answered, as the WS-Security verifiers read
/// it.
struct EngineResult {
    signature_valid: bool,
    signature_error: Option<String>,
    references_valid: bool,
    /// The first Reference that failed, and its reason.
    bad: Option<(String, String)>,
}

/// `firstByLocal()`: the first descendant (never the node itself) with a
/// local name, in any namespace.
fn first_by_local(doc: &Document, root: NodeId, local: &str) -> Option<NodeId> {
    first_descendant(doc, root, None, local)
}

/// `xmldsig.verifyXml(signatureXml, { referencedXml, allowedTransforms,
/// verifier })`: the signature as its own document, the References resolved
/// in it and then in the envelope.
fn engine_verify(
    signature_xml: &str,
    referenced_xml: &str,
    verifier: &dyn Fn(&[u8], &[u8]) -> bool,
) -> EngineResult {
    let fail = || EngineResult {
        signature_valid: false,
        signature_error: None,
        references_valid: false,
        bad: None,
    };
    let Ok(copy) = Document::parse(signature_xml) else {
        return fail();
    };
    let Ok(envelope) = Document::parse(referenced_xml) else {
        return fail();
    };
    let Some(root) = copy.document_element() else {
        return fail();
    };
    let sig = if copy.element(root).is_some_and(|e| e.local == "Signature") {
        Some(root)
    } else {
        first_by_local(&copy, Document::ROOT, "Signature")
    };
    let Some(sig) = sig else {
        return fail();
    };
    let si = direct_child(&copy, sig, "SignedInfo", None);
    let sv = direct_child(&copy, sig, "SignatureValue", None);
    let (Some(si), Some(sv)) = (si, sv) else {
        return fail();
    };
    let sig_alg = first_by_local(&copy, si, "SignatureMethod")
        .map(|m| attr(&copy, m, "Algorithm").to_string())
        .unwrap_or_default();
    let cm = first_by_local(&copy, si, "CanonicalizationMethod");
    let c14n_alg = cm
        .map(|c| attr(&copy, c, "Algorithm").to_string())
        .unwrap_or_else(|| C14N_EXCLUSIVE.to_string());
    if signature_method(&sig_alg).is_none() || c14n_method(&c14n_alg).is_none()
    {
        return fail();
    }
    let cm_prefixes = cm
        .and_then(|c| first_by_local(&copy, c, "InclusiveNamespaces"))
        .and_then(|i| prefix_set(attr(&copy, i, "PrefixList")));
    for t in all_descendants(&copy, si, Some(DS_NS), "Transform") {
        if !XML_ACCEPTED_TRANSFORMS.contains(&attr(&copy, t, "Algorithm")) {
            return fail();
        }
    }
    let si_octets = canonicalize_by(&copy, si, &c14n_alg, cm_prefixes, None)
        .unwrap_or_default();
    let signature_bytes =
        decode_base64(&strip_ws(&copy.text(sv))).unwrap_or_default();
    let signature_valid = verifier(&si_octets, &signature_bytes);

    let mut outcomes: Vec<(String, bool, String)> = Vec::new();
    for r in all_descendants(&copy, si, None, "Reference") {
        let uri = attr(&copy, r, "URI").to_string();
        let digest_uri = first_by_local(&copy, r, "DigestMethod")
            .map(|d| attr(&copy, d, "Algorithm").to_string())
            .unwrap_or_default();
        let declared = first_by_local(&copy, r, "DigestValue")
            .map(|d| strip_ws(&copy.text(d)))
            .unwrap_or_default();
        let bare = uri.strip_prefix('#').unwrap_or(&uri);
        // In the copy first, then in the envelope.
        let (doc, target, sig_node) = if uri.is_empty() {
            match envelope.document_element() {
                Some(t) => (&envelope, t, usize::MAX),
                None => {
                    outcomes.push((
                        uri,
                        false,
                        "the referenced element was not found".to_string(),
                    ));
                    continue;
                }
            }
        } else if let Some(t) = find_by_id(&copy, Document::ROOT, bare, None) {
            (&copy, t, sig)
        } else if let Some(t) =
            find_by_id(&envelope, Document::ROOT, bare, None)
        {
            (&envelope, t, usize::MAX)
        } else {
            outcomes.push((
                uri,
                false,
                "the referenced element was not found".to_string(),
            ));
            continue;
        };
        let transforms = read_transforms(&copy, r);
        let octets =
            match transform_octets(doc, target, &transforms, sig_node, None) {
                Ok(o) => o,
                Err(e) => {
                    outcomes.push((uri, false, e.to_string()));
                    continue;
                }
            };
        let Some(hash) = digest_method(&digest_uri) else {
            outcomes.push((
                uri,
                false,
                format!("Unsupported DigestMethod: {}", digest_uri),
            ));
            continue;
        };
        match hash_b64(hash, &octets) {
            Some(computed) if computed == declared => {
                outcomes.push((uri, true, String::new()))
            }
            _ => outcomes.push((
                uri,
                false,
                "the digest does not match".to_string(),
            )),
        }
    }
    let references_valid = !outcomes.is_empty() && outcomes.iter().all(|o| o.1);
    EngineResult {
        signature_valid,
        signature_error: None,
        references_valid,
        bad: outcomes
            .into_iter()
            .find(|o| !o.1)
            .map(|(uri, _, reason)| (uri, reason)),
    }
}

/// The SignatureMethod element of the envelope's one signature, which Node
/// locates again in a fresh parse: the first `Security` of the `Header`, its
/// first xmldsig `Signature`.
fn method_element(doc: &Document) -> Option<NodeId> {
    let header = child(doc, doc.document_element(), "Header", None);
    let security = child(doc, header, "Security", None);
    let sig = child(doc, security, "Signature", Some(DS_NS));
    let si = child(doc, sig, "SignedInfo", Some(DS_NS));
    child(doc, si, "SignatureMethod", Some(DS_NS))
}

fn signature_element(doc: &Document) -> Option<NodeId> {
    let header = child(doc, doc.document_element(), "Header", None);
    let security = child(doc, header, "Security", None);
    child(doc, security, "Signature", Some(DS_NS))
}

/// `crypto.verifyWsSecuritySignature()`: the message signature verified
/// with the certificate the CALLER resolved from the reading's key
/// reference (PEM or base64 DER), after every guard the reading applies.
#[tracing::instrument(skip_all)]
pub fn verify_ws_security_signature(
    xml: &str,
    cert_pem: Option<&str>,
    policy: &XmlPolicy,
) -> WsSecurityReading {
    let reading = read_ws_security_signature(xml, policy);
    if !reading.present || !reading.ok {
        return reading;
    }
    let found = match verification_key_from(cert_pem, None) {
        Ok(k) => k,
        Err(problem) => {
            return reading.now_refused(
                codes::STS_KEYS_0014,
                format!("the signature cannot be checked: {}", problem),
            )
        }
    };
    let Ok(doc) = Document::parse(xml) else {
        return reading;
    };
    let method_uri = reading.signature_method.clone().unwrap_or_default();
    let pss = if signature_method(&method_uri)
        .is_some_and(|m| m.family == Family::RsaPss)
        && method_uri == format!("{}rsa-pss", XMLDSIG_MORE_2007)
    {
        method_element(&doc).map(|m| pss_parameters(&doc, m))
    } else {
        None
    };
    if let Some(Err(problem)) = &pss {
        return reading.now_refused(
            codes::STS_KEYS_0061,
            format!("the RSASSA-PSS signature cannot be checked: {}", problem),
        );
    }
    let pss = pss.and_then(Result::ok);
    let Some(sig) = signature_element(&doc) else {
        return reading;
    };
    let signature_xml =
        without_certificate_text(&serialize_detached(&doc, sig));
    let method = signature_method(&method_uri);
    let verifier = |octets: &[u8], signature: &[u8]| {
        method.is_some_and(|m| {
            verify_signature_value(
                m, &found.key, octets, signature, pss, policy,
            )
        })
    };
    let result = engine_verify(&signature_xml, xml, &verifier);
    if !result.signature_valid {
        let mut out = reading.now_refused(
            codes::STS_KEYS_0012,
            format!(
                "the signature value does not verify with the certificate \
                 the security header names{}",
                result
                    .signature_error
                    .map(|e| format!(": {}", e))
                    .unwrap_or_default()
            ),
        );
        out.signature_valid = Some(false);
        return out;
    }
    if !result.references_valid {
        let (uri, reason) = result.bad.unwrap_or_default();
        let mut out = reading.now_refused(
            codes::STS_KEYS_0013,
            format!(
                "the signature value is genuine but the part {}was altered \
                 after it was signed{}",
                if uri.is_empty() {
                    String::new()
                } else {
                    format!("{} ", uri)
                },
                if reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", reason)
                }
            ),
        );
        out.signature_valid = Some(true);
        out.references_valid = Some(false);
        return out;
    }
    WsSecurityReading {
        ok: true,
        signature_valid: Some(true),
        references_valid: Some(true),
        signer_subject: Some(found.subject),
        ..reading
    }
}

/// `crypto.verifyWsSecurityHmac()`: a message signature made with a shared
/// key — the session key a Kerberos token established (#658) — after every
/// guard the reading applies. The method must be an HMAC one with no
/// `HMACOutputLength` (a truncated HMAC is CVE-2009-0217's forgery), and the
/// value is compared in constant time.
#[tracing::instrument(skip_all)]
pub fn verify_ws_security_hmac(
    xml: &str,
    key: &[u8],
    policy: &XmlPolicy,
) -> WsSecurityReading {
    let reading = read_ws_security_signature(xml, policy);
    if !reading.present || !reading.ok {
        return reading;
    }
    let method_uri = reading.signature_method.clone().unwrap_or_default();
    let row = signature_method(&method_uri);
    let Some(hash) = row
        .filter(|m| m.family == Family::Hmac && !key.is_empty())
        .and_then(|m| m.hash)
    else {
        return reading.now_refused(
            codes::STS_KEYS_0061,
            format!(
                "a signature keyed by a Kerberos token is an HMAC; this one \
                 is {}",
                if method_uri.is_empty() {
                    "nothing"
                } else {
                    method_uri.as_str()
                }
            ),
        );
    };
    let Ok(doc) = Document::parse(xml) else {
        return reading;
    };
    if method_element(&doc)
        .and_then(|m| direct_child(&doc, m, "HMACOutputLength", None))
        .is_some()
    {
        return reading.now_refused(
            codes::STS_KEYS_0061,
            "the SignatureMethod carries an HMACOutputLength; a truncated \
             HMAC is refused (CVE-2009-0217)"
                .to_string(),
        );
    }
    let Some(sig) = signature_element(&doc) else {
        return reading;
    };
    let signature_xml = serialize_detached(&doc, sig);
    let verifier = |octets: &[u8], given: &[u8]| {
        hmac(hash, key, octets).is_some_and(|expected| {
            given.len() == expected.len() && memcmp::eq(given, &expected)
        })
    };
    let result = engine_verify(&signature_xml, xml, &verifier);
    if !result.signature_valid {
        let mut out = reading.now_refused(
            codes::STS_KEYS_0012,
            "the HMAC does not verify with the Kerberos token's session key"
                .to_string(),
        );
        out.signature_valid = Some(false);
        return out;
    }
    if !result.references_valid {
        let (uri, _) = result.bad.unwrap_or_default();
        let mut out = reading.now_refused(
            codes::STS_KEYS_0013,
            format!(
                "the HMAC is genuine but the part {}was altered after it \
                 was signed",
                if uri.is_empty() {
                    String::new()
                } else {
                    format!("{} ", uri)
                }
            ),
        );
        out.signature_valid = Some(true);
        out.references_valid = Some(false);
        return out;
    }
    WsSecurityReading {
        ok: true,
        signature_valid: Some(true),
        references_valid: Some(true),
        ..reading
    }
}

fn hmac(hash: Hash, key: &[u8], octets: &[u8]) -> Option<Vec<u8>> {
    let key = PKey::hmac(key).ok()?;
    let mut signer = Signer::new(hash.md(), &key).ok()?;
    signer.sign_oneshot_to_vec(octets).ok()
}

// ---------------------------------------------------------------------------
// The signer.
// ---------------------------------------------------------------------------

/// How [`sign_ws_security`] signs.
pub enum WsSecurityKey<'a> {
    /// An RSA private key and the certificate its KeyInfo carries
    /// (PKCS#1 v1.5, one of the four RSA methods `sigAlgSpec()` names).
    Rsa {
        key: &'a PKeyRef<Private>,
        cert_pem: &'a str,
    },
    /// A shared key (an HMAC method), with the caller's KeyInfo content.
    Shared {
        key: &'a [u8],
        key_info_xml: &'a str,
    },
}

/// `xmldsig.signWsSecurity()`'s options.
pub struct WsSecuritySignOptions<'a> {
    /// The SignatureMethod; RSA-SHA256 when `None`.
    pub sig_alg: Option<&'a str>,
    pub key: WsSecurityKey<'a>,
    /// Whether the `wsu:Timestamp` is a second Reference.
    pub sign_timestamp: bool,
}

/// `xmldsig.signWsSecurity()`: a `ds:Signature` over the SOAP Body (and the
/// Timestamp) inserted first in the security header. RSA signatures are the
/// same BYTES Node makes.
#[tracing::instrument(skip_all)]
pub fn sign_ws_security(
    soap_xml: &str,
    o: &WsSecuritySignOptions,
) -> CryptoResult<String> {
    let sig_alg = o.sig_alg.unwrap_or(RSA_SHA256);
    let shared = signature_method(sig_alg)
        .filter(|m| m.family == Family::Hmac)
        .and_then(|m| m.hash.map(|h| (h, m.default_digest)));
    // `sigAlgSpec()` for RSA; an HMAC takes the post-quantum path's
    // `forgeMdFor(pqSpec.digestUri)`.
    let (hash, digest_uri) = match (&o.key, shared) {
        (WsSecurityKey::Shared { .. }, Some((_, digest))) => {
            (md_for(digest), digest)
        }
        (WsSecurityKey::Rsa { .. }, None) => {
            rsa_spec(sig_alg).unwrap_or((Hash::Sha256, SHA256))
        }
        _ => {
            return Err(CryptoError::new(format!(
                "signWsSecurity: {} needs the other kind of key",
                sig_alg
            )))
        }
    };
    let mut doc = Document::parse(soap_xml)
        .map_err(|e| CryptoError::new(e.to_string()))?;
    let security = first_by_local(&doc, Document::ROOT, "Security")
        .ok_or_else(|| {
            CryptoError::new(
                "No <wsse:Security> header to hold the signature — enable a \
                 timestamp or a credential.",
            )
        })?;
    let mut targets = Vec::new();
    if let Some(body) = first_by_local(&doc, Document::ROOT, "Body") {
        targets.push(body);
    }
    if o.sign_timestamp {
        if let Some(ts) = first_by_local(&doc, Document::ROOT, "Timestamp") {
            targets.push(ts);
        }
    }
    let mut refs = String::new();
    for t in targets {
        let id = doc
            .element(t)
            .and_then(|e| {
                e.attrs.iter().find(|a| {
                    a.local == "Id" && a.ns.as_deref() == Some(WSU_NS)
                })
            })
            .map(|a| a.value.clone())
            .or_else(|| {
                doc.element(t)
                    .and_then(|e| e.attr("wsu:Id"))
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let octets = c14n::exclusive(&doc, t, &c14n::Options::default());
        let digest = digest_b64(hash, octets.as_bytes())?;
        refs.push_str(&format!(
            "<ds:Reference URI=\"#{}\"><ds:Transforms><ds:Transform \
             Algorithm=\"{}\"/></ds:Transforms><ds:DigestMethod \
             Algorithm=\"{}\"/><ds:DigestValue>{}</ds:DigestValue>\
             </ds:Reference>",
            id, C14N_EXCLUSIVE, digest_uri, digest
        ));
    }
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{}\"><ds:CanonicalizationMethod \
         Algorithm=\"{}\"/><ds:SignatureMethod Algorithm=\"{}\"/>{}\
         </ds:SignedInfo>",
        DS_NS, C14N_EXCLUSIVE, sig_alg, refs
    );
    let si_doc = Document::parse(&signed_info)
        .map_err(|e| CryptoError::new(e.to_string()))?;
    let si_root = si_doc
        .document_element()
        .ok_or_else(|| CryptoError::new("no SignedInfo"))?;
    let si_canon = c14n::exclusive(&si_doc, si_root, &c14n::Options::default());
    let (value, key_info) = match &o.key {
        WsSecurityKey::Rsa { key, cert_pem } => {
            let mut signer = Signer::new(hash.md(), key)?;
            signer.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
            (
                signer.sign_oneshot_to_vec(si_canon.as_bytes())?,
                format!(
                    "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}\
                     </ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
                    cert_pem_to_b64(cert_pem)
                ),
            )
        }
        WsSecurityKey::Shared { key, key_info_xml } => {
            let (h, _) = shared.ok_or_else(|| CryptoError::new("no HMAC"))?;
            (
                hmac(h, key, si_canon.as_bytes())
                    .ok_or_else(|| CryptoError::new("the HMAC failed"))?,
                format!("<ds:KeyInfo>{}</ds:KeyInfo>", key_info_xml),
            )
        }
    };
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{}\">{}<ds:SignatureValue>{}\
         </ds:SignatureValue>{}</ds:Signature>",
        DS_NS,
        signed_info,
        standard_b64(&value),
        key_info
    );
    let node = import(&mut doc, &signature)?;
    let first = doc.children(security).first().copied();
    doc.insert_before(security, node, first);
    Ok(doc.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_serials_in_hex() {
        assert_eq!(decimal_to_hex("0"), "0");
        assert_eq!(decimal_to_hex("15"), "f");
        assert_eq!(decimal_to_hex("007"), "7");
        assert_eq!(
            decimal_to_hex("340282366920938463463374607431768211455"),
            "ffffffffffffffffffffffffffffffff"
        );
        assert_eq!(decimal_to_hex("4294967296"), "100000000");
    }

    #[test]
    fn certificate_text_emptied() {
        assert_eq!(
            without_certificate_text(
                "<ds:X509Certificate a=\"1\">MIIB\n</ds:X509Certificate>\
                 <X509Certificate>x</X509Certificate>\
                 <X509CertificateX>y</X509CertificateX>"
            ),
            "<ds:X509Certificate a=\"1\"></ds:X509Certificate>\
             <X509Certificate></X509Certificate>\
             <X509CertificateX>y</X509CertificateX>"
        );
    }

    #[test]
    fn detached_copy_declares_what_it_uses() {
        let doc = Document::parse(
            "<s:E xmlns:s=\"urn:s\" xmlns:ds=\"urn:ds\" xmlns:u=\"urn:u\">\
             <ds:Sig u:Id=\"a\"><ds:I/></ds:Sig></s:E>",
        )
        .unwrap();
        let root = doc.document_element().unwrap();
        let sig = doc.child_elements(root)[0];
        assert_eq!(
            serialize_detached(&doc, sig),
            "<ds:Sig xmlns:u=\"urn:u\" u:Id=\"a\" xmlns:ds=\"urn:ds\">\
             <ds:I/></ds:Sig>"
        );
    }
}
