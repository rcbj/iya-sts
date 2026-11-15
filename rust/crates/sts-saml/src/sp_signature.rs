// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A SERVICE PROVIDER'S SIGNATURE (`saml/request_signature.ts`, #37): whether
//! a message — an AuthnRequest, a LogoutRequest or LogoutResponse, an
//! ArtifactResolve — is signed by the service provider it names, on the
//! Redirect, POST and SimpleSign bindings and for the SOAP responders'
//! callers. Node's four decisions, kept:
//!
//! 1. a signature that is PRESENT is verified in every mode, and refused
//!    when it does not verify (STS-SAML-0061), cannot be checked (0062) or
//!    is SHA-1 while that is off (0073);
//! 2. the trust anchor is the REGISTERED certificate
//!    (`samlSigningCertificate`), never the one the message carries;
//! 3. with none registered a signature is recorded, not verified
//!    (`no-certificate`), and counts as unsigned;
//! 4. whether one may be absent is `saml2.requireSignedAuthnRequests`
//!    (`auto` follows the mode), and a service provider whose metadata says
//!    `AuthnRequestsSigned="true"` is held to its word.
//!
//! The Redirect binding signs the octets `SAMLRequest=…&RelayState=…&SigAlg=…`
//! EXACTLY AS THEY ARRIVED (the first of each name, still percent-encoded);
//! a signed parameter that comes twice is not checkable. SimpleSign signs
//! the raw XML, base64-decoded from the form.
//!
//! WHAT A CALLER HANDS IN: the realm's XML signature policy, the setting
//! and the mode's answer ([`Requirement`]), and the paranoid PKI door
//! (`certificate_trust.pinnedSync()`, [`PinnedDoor`]) a verified signature's
//! certificate is held to under #1360.

use sts_core::errors::{codes, ErrorCode};
use sts_crypto::xmldsig::{self, uri::DS_NS, VerifyOptions, XmlPolicy};
use sts_xml::dom::Document;

/// `assess()`'s answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assessment {
    pub signed: bool,
    /// `unsigned`, `no-certificate`, `verified` or `failed`.
    pub outcome: &'static str,
    /// `redirect`, `simplesign`, `post` or ''.
    pub binding: &'static str,
    pub sig_alg: String,
    pub weak: bool,
    pub why: String,
    pub error_code: Option<ErrorCode>,
    pub key_info_certificate: String,
    pub registered: usize,
}

/// What `assess()` is asked.
#[derive(Clone, Debug, Default)]
pub struct AssessSpec<'a> {
    /// `redirect` for a GET, `post` for a form POST.
    pub binding: &'a str,
    /// The query string as it arrived, without the '?'.
    pub raw_query: &'a str,
    /// The decoded parameters, each name's values (more than one is a
    /// repeated control).
    pub params: &'a [(String, Vec<String>)],
    pub xml: &'a str,
    pub root_local_name: &'a str,
    /// `SAMLRequest`, `SAMLResponse`, or '' for a SOAP caller.
    pub message_field: &'a str,
    /// The entry's `samlSigningCertificate` values.
    pub registered: &'a [String],
    /// The use case the signer is held to: `saml-signer` unless named.
    pub purpose: &'a str,
}

/// `certificate_trust.pinnedSync(purpose, certPem, { named: true })`: the
/// registered certificate in date, allowed to sign, not revoked — under
/// paranoid PKI mode, and a pass otherwise.
pub trait PinnedDoor {
    fn pinned(
        &self,
        purpose: &str,
        cert_pem: &str,
    ) -> Result<(), (ErrorCode, String)>;
}

/// The door where paranoid PKI mode does not apply: every pin holds.
pub struct NoDoor;

impl PinnedDoor for NoDoor {
    #[tracing::instrument(level = "debug", skip_all)]
    fn pinned(&self, _: &str, _: &str) -> Result<(), (ErrorCode, String)> {
        Ok(())
    }
}

/// Whether this service provider's requests must be signed: what decides
/// it, Node's order.
#[derive(Clone, Debug, Default)]
pub struct Requirement {
    /// The entry's `samlSpAuthnRequestsSigned`.
    pub declared: String,
    /// `saml2.requireSignedAuthnRequests`: `auto`, `on`, `off`.
    pub setting: String,
    /// `mode.acceptsUnsignedSamlRequests()`.
    pub accepts_unsigned: bool,
}

impl Requirement {
    /// `requiresSignedRequests(fields)`: `(required, why)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn required(&self) -> (bool, String) {
        if self.declared == "TRUE" {
            return (
                true,
                "its consumed metadata says AuthnRequestsSigned=\"true\""
                    .to_string(),
            );
        }
        let asked = if self.setting.is_empty() {
            "auto"
        } else {
            self.setting.as_str()
        };
        if asked == "on" || asked == "off" {
            return (
                asked == "on",
                format!("saml2.requireSignedAuthnRequests is {}", asked),
            );
        }
        let required = !self.accepts_unsigned;
        (
            required,
            format!(
                "saml2.requireSignedAuthnRequests is auto and this realm is \
                 in {} mode",
                if required { "PRODUCT" } else { "development" }
            ),
        )
    }
}

/// `registeredCertificates(fields)`: each value's whitespace and PEM armour
/// taken off, deduplicated, in order.
#[tracing::instrument(level = "debug", skip_all)]
pub fn registered_certificates(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        let one: String = v.chars().filter(|c| !c.is_whitespace()).collect();
        if one.is_empty() {
            continue;
        }
        let der = strip_armour(&one);
        if !der.is_empty() && !out.contains(&der) {
            out.push(der);
        }
    }
    out
}

/// `.replace(/-----[^-]+-----/g, '')`.
fn strip_armour(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find("-----") {
        let after = &rest[at + 5..];
        match after.find("-----") {
            Some(end) if end > 0 && !after[..end].contains('-') => {
                out.push_str(&rest[..at]);
                rest = &after[end + 5..];
            }
            _ => {
                out.push_str(&rest[..at + 1]);
                rest = &rest[at + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `pemOf(der)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn pem_of(der: &str) -> String {
    let lines: Vec<&str> = der
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// `decodeURIComponent(name.replace(/\+/g, ' '))`, the name kept as it was
/// when it does not decode.
fn decode_name(name: &str) -> String {
    let spaced = name.replace('+', " ");
    let b = spaced.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = spaced.get(i + 1..i + 3);
            match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                None => return name.to_string(),
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| name.to_string())
}

/// `rawParameters(rawQuery)`: the first occurrence of each name with its
/// value still percent-encoded, and the names that came again.
#[tracing::instrument(level = "debug", skip_all)]
pub fn raw_parameters(raw_query: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut repeated: Vec<String> = Vec::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.find('=') {
            Some(at) => (&pair[..at], &pair[at + 1..]),
            None => (pair, ""),
        };
        let decoded = decode_name(name);
        if out.iter().any(|(n, _)| *n == decoded) {
            if !repeated.contains(&decoded) {
                repeated.push(decoded);
            }
        } else {
            out.push((decoded, value.to_string()));
        }
    }
    (out, repeated)
}

/// `redirectOctets(rawQuery, messageField)`: '' when a parameter it needs
/// is missing or repeated.
#[tracing::instrument(level = "debug", skip_all)]
pub fn redirect_octets(raw_query: &str, message_field: &str) -> String {
    let (raw, repeated) = raw_parameters(raw_query);
    if [message_field, "RelayState", "SigAlg", "Signature"]
        .iter()
        .any(|n| repeated.iter().any(|r| r == n))
    {
        return String::new();
    }
    let get = |n: &str| raw.iter().find(|(k, _)| k == n).map(|(_, v)| v);
    let (Some(message), Some(sig_alg)) = (get(message_field), get("SigAlg"))
    else {
        return String::new();
    };
    let mut octets = format!("{}={}", message_field, message);
    if let Some(relay) = get("RelayState") {
        octets.push_str(&format!("&RelayState={}", relay));
    }
    octets.push_str(&format!("&SigAlg={}", sig_alg));
    octets
}

/// One control's value: `None` absent, `Some(None)` repeated.
fn single<'a>(
    params: &'a [(String, Vec<String>)],
    name: &str,
) -> Option<Option<&'a str>> {
    params.iter().find(|(n, _)| n == name).map(|(_, v)| {
        if v.len() == 1 {
            Some(v[0].as_str())
        } else {
            None
        }
    })
}

/// `simpleSignOctets(params, messageField)`: the message base64-decoded,
/// then RelayState and SigAlg; '' when one it needs is missing or repeated.
#[tracing::instrument(level = "debug", skip_all)]
pub fn simple_sign_octets(
    params: &[(String, Vec<String>)],
    message_field: &str,
) -> String {
    let message = single(params, message_field);
    let sig_alg = single(params, "SigAlg");
    let relay = single(params, "RelayState");
    let (Some(Some(message)), Some(Some(sig_alg))) = (message, sig_alg) else {
        return String::new();
    };
    if message.is_empty()
        || sig_alg.is_empty()
        || relay == Some(None)
        || single(params, "Signature") == Some(None)
    {
        return String::new();
    }
    let raw = String::from_utf8_lossy(&crate::binding::node_base64(message))
        .into_owned();
    format!(
        "{}={}{}&SigAlg={}",
        message_field,
        raw,
        match relay {
            Some(Some(r)) => format!("&RelayState={}", r),
            _ => String::new(),
        },
        sig_alg
    )
}

/// The root's own ds:Signature: its method, canonicalization, KeyInfo
/// certificate and digests.
struct Enveloped {
    sig_alg: String,
    key_info_certificate: String,
    digest_methods: Vec<String>,
}

fn enveloped_signature(xml: &str, root_local: &str) -> Option<Enveloped> {
    let doc = Document::parse(xml).ok()?;
    let root = doc.document_element()?;
    if doc.element(root)?.local != root_local {
        return None;
    }
    let sig = doc.child_elements(root).into_iter().find(|&c| {
        doc.element(c).is_some_and(|e| {
            e.local == "Signature" && e.ns.as_deref() == Some(DS_NS)
        })
    })?;
    let named = |local: &str| -> Vec<usize> {
        doc.descendants(sig)
            .into_iter()
            .skip(1)
            .filter(|&n| {
                doc.element(n).is_some_and(|e| {
                    e.local == local && e.ns.as_deref() == Some(DS_NS)
                })
            })
            .collect()
    };
    let attr = |n: usize| {
        doc.element(n)
            .and_then(|e| e.attr("Algorithm"))
            .unwrap_or("")
            .to_string()
    };
    Some(Enveloped {
        sig_alg: named("SignatureMethod")
            .first()
            .map(|&m| attr(m))
            .unwrap_or_default(),
        key_info_certificate: named("X509Certificate")
            .first()
            .map(|&c| {
                doc.text(c).chars().filter(|c| !c.is_whitespace()).collect()
            })
            .unwrap_or_default(),
        digest_methods: named("DigestMethod").into_iter().map(attr).collect(),
    })
}

fn param<'a>(params: &'a [(String, Vec<String>)], name: &str) -> &'a str {
    params
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.first())
        .map(String::as_str)
        .unwrap_or("")
}

/// `assess(spec)`: one message's signature against the registered
/// certificates. Never panics.
#[tracing::instrument(level = "debug", skip_all)]
pub fn assess(
    spec: &AssessSpec,
    policy: &XmlPolicy,
    door: &dyn PinnedDoor,
) -> Assessment {
    let registered = registered_certificates(spec.registered);
    let signature = param(spec.params, "Signature");
    let simple_sign = spec.binding == "post"
        && !signature.is_empty()
        && !spec.message_field.is_empty();
    let detached =
        (spec.binding == "redirect" && !signature.is_empty()) || simple_sign;
    let enveloped = if detached {
        None
    } else {
        enveloped_signature(spec.xml, spec.root_local_name)
    };
    let mut answer = Assessment {
        signed: detached || enveloped.is_some(),
        outcome: "unsigned",
        binding: if detached {
            if simple_sign {
                "simplesign"
            } else {
                "redirect"
            }
        } else if enveloped.is_some() {
            "post"
        } else {
            ""
        },
        sig_alg: if detached {
            param(spec.params, "SigAlg").to_string()
        } else {
            enveloped
                .as_ref()
                .map(|e| e.sig_alg.clone())
                .unwrap_or_default()
        },
        key_info_certificate: enveloped
            .as_ref()
            .map(|e| e.key_info_certificate.clone())
            .unwrap_or_default(),
        registered: registered.len(),
        ..Assessment::default()
    };
    let made = xmldsig::algorithm_verdict(
        &answer.sig_alg,
        &enveloped
            .as_ref()
            .map(|e| e.digest_methods.clone())
            .unwrap_or_default(),
        policy,
    );
    answer.weak = made.weak;
    if !answer.signed {
        answer.why =
            format!("the {} carries no signature", spec.root_local_name);
        return answer;
    }
    if registered.is_empty() {
        answer.outcome = "no-certificate";
        answer.why = "it is signed, and this service provider has no \
                      registered signing certificate (samlSigningCertificate) \
                      to check it against, so it is NOT verified"
            .to_string();
        return answer;
    }
    let mut octets = String::new();
    if detached {
        octets = if simple_sign {
            simple_sign_octets(spec.params, spec.message_field)
        } else {
            redirect_octets(spec.raw_query, spec.message_field)
        };
        if octets.is_empty() {
            answer.outcome = "failed";
            answer.error_code = Some(codes::STS_SAML_0062);
            answer.why = format!(
                "a Signature parameter arrived without the {} and SigAlg it \
                 signs (or with one of them repeated), so there is nothing \
                 to verify it over",
                spec.message_field
            );
            return answer;
        }
    }
    let mut last_why = String::new();
    let mut checkable = false;
    let purpose = if spec.purpose.is_empty() {
        "saml-signer"
    } else {
        spec.purpose
    };
    for (i, der) in registered.iter().enumerate() {
        let cert_pem = pem_of(der);
        let (ok, why, code, usable, present, method) = if detached {
            let v = xmldsig::verify_query_string(
                &octets,
                Some(signature),
                &answer.sig_alg,
                Some(&cert_pem),
                policy,
            );
            (v.ok, v.why, v.code, v.usable, true, v.signature_method)
        } else {
            let v = xmldsig::verify_xml_signature(
                spec.xml,
                &VerifyOptions {
                    element: spec.root_local_name,
                    cert_pem: Some(&cert_pem),
                    policy: policy.clone(),
                    ..VerifyOptions::default()
                },
            );
            (v.ok, v.why, v.code, false, v.present, v.signature_method)
        };
        if ok {
            if let Err((code, why)) = door.pinned(purpose, &cert_pem) {
                answer.outcome = "failed";
                answer.error_code = Some(code);
                answer.why = format!(
                    "the signature verified against a registered certificate \
                     that is refused: {}",
                    why
                );
                return answer;
            }
            answer.outcome = "verified";
            if !method.is_empty() {
                answer.sig_alg = method;
            }
            answer.why = format!(
                "verified against registered certificate {} of {}{}",
                i + 1,
                registered.len(),
                if answer.weak {
                    format!(" — with a WEAK hash ({})", answer.sig_alg)
                } else {
                    String::new()
                }
            );
            return answer;
        }
        last_why = if why.is_empty() {
            "it did not verify".to_string()
        } else {
            why
        };
        if code == Some(codes::STS_KEYS_0062) {
            answer.outcome = "failed";
            answer.error_code = Some(codes::STS_SAML_0073);
            answer.why = last_why;
            return answer;
        }
        let wrong = if detached {
            usable
        } else {
            present
                && (code == Some(codes::STS_KEYS_0012)
                    || code == Some(codes::STS_KEYS_0013))
        };
        if wrong {
            checkable = true;
        }
    }
    answer.outcome = "failed";
    answer.error_code = Some(if checkable {
        codes::STS_SAML_0061
    } else {
        codes::STS_SAML_0062
    });
    answer.why = if checkable {
        format!(
            "the signature does not verify against any of the {} registered \
             certificate(s): {}",
            registered.len(),
            last_why
        )
    } else {
        format!("the signature could not be checked: {}", last_why)
    };
    answer
}

/// `refusal(assessment, fields)`: `(refuse, code, why)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn refusal(
    a: &Assessment,
    need: &Requirement,
) -> (bool, Option<ErrorCode>, String) {
    if a.outcome == "failed" {
        return (
            true,
            a.error_code,
            format!("The request's signature was refused: {}.", a.why),
        );
    }
    if a.outcome == "verified" {
        return (false, None, String::new());
    }
    let (required, why) = need.required();
    if !required {
        return (false, None, String::new());
    }
    (
        true,
        Some(codes::STS_SAML_0063),
        format!(
            "A signed request is required here ({}), and {}. {}",
            why,
            a.why,
            if a.outcome == "no-certificate" {
                "Register the service provider's signing certificate — \
                 consume its metadata, or set it on the SAML 2.0 console page \
                 — or confirm the one its request carried, if it is genuinely \
                 that service provider's."
            } else {
                "Have the service provider sign its requests."
            }
        ),
    )
}

/// `summary(assessment)`: `<outcome> <binding> <sigAlg>[ weak]`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn summary(a: &Assessment) -> String {
    format!(
        "{} {} {}{}",
        a.outcome,
        if a.binding.is_empty() { "-" } else { a.binding },
        if a.sig_alg.is_empty() {
            "-"
        } else {
            a.sig_alg.as_str()
        },
        if a.weak { " weak" } else { "" }
    )
}

/// `authenticateSoapCaller()`'s answer: `via` is `signature`, `tls` or
/// `none`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoapCaller {
    pub refuse: bool,
    pub error_code: Option<ErrorCode>,
    pub why: String,
    pub via: &'static str,
    pub assessment: Assessment,
}

/// `authenticateSoapCaller(spec)`: the caller of a SOAP responder (artifact
/// resolution), by a signature verifying against the party's registered
/// certificates or a TLS client certificate that is one of them; anonymous
/// is refused where signed requests are required (STS-SAML-0077).
#[tracing::instrument(level = "debug", skip_all)]
pub fn authenticate_soap_caller(
    xml: &str,
    root_local_name: &str,
    registered: &[String],
    tls_certificate: &str,
    need: &Requirement,
    policy: &XmlPolicy,
    door: &dyn PinnedDoor,
) -> SoapCaller {
    let assessment = assess(
        &AssessSpec {
            binding: "post",
            xml,
            root_local_name,
            registered,
            ..AssessSpec::default()
        },
        policy,
        door,
    );
    if assessment.outcome == "failed" {
        return SoapCaller {
            refuse: true,
            error_code: assessment.error_code,
            why: format!(
                "the {}'s signature was refused: {}",
                root_local_name, assessment.why
            ),
            via: "signature",
            assessment,
        };
    }
    if assessment.outcome == "verified" {
        return SoapCaller {
            refuse: false,
            error_code: None,
            why: assessment.why.clone(),
            via: "signature",
            assessment,
        };
    }
    let tls: String = tls_certificate
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if !tls.is_empty() && registered_certificates(registered).contains(&tls) {
        return SoapCaller {
            refuse: false,
            error_code: None,
            why: "the TLS client certificate is one of the party's \
                  registered signing certificates"
                .to_string(),
            via: "tls",
            assessment,
        };
    }
    let (required, need_why) = need.required();
    if required {
        return SoapCaller {
            refuse: true,
            error_code: Some(codes::STS_SAML_0077),
            why: format!(
                "the caller is not authenticated — {}{} — and an \
                 authenticated caller is required here ({})",
                assessment.why,
                if tls.is_empty() {
                    ", and no TLS client certificate was presented"
                } else {
                    ", and the TLS client certificate is not one of its \
                     registered certificates"
                },
                need_why
            ),
            via: "none",
            assessment,
        };
    }
    SoapCaller {
        refuse: false,
        error_code: None,
        why: format!(
            "the caller is not authenticated ({}), which {} allows",
            assessment.why, need_why
        ),
        via: "none",
        assessment,
    }
}
