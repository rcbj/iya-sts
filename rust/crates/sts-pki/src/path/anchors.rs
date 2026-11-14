// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Who may enter a truststore (#1360): `pki.js`'s `anchorFieldsOf()`,
//! `anchorProblem()` and `anchorProblemSync()`.
//!
//! An anchor is a self-signed certificate authority that verifies under its
//! own key; an intermediate is a certificate authority that chains to an
//! anchor already held. Both are held to the field checks for the role with
//! keyCertSign asked ([`crate::fields`]). A leaf is never admitted: a leaf to
//! pin goes on the entry or relationship that uses it.
//!
//! Node has two doors because two of its callers are synchronous: the
//! asynchronous one builds a path through held intermediates, the
//! synchronous one asks one hop and lets OpenSSL verify a self-signature.
//! Their sentences differ and both are kept. Which store the held anchors
//! come from is the caller's (`common/signer_truststore.ts`, a later phase).

use chrono::Utc;
use sts_core::errors::{codes, ErrorCode};

use super::build::{
    path_signed, verify_issued_directly, verify_path_to_anchors, PathOptions,
};
use super::entry::Entry;
use crate::fields::{
    certificate_facts, certificate_field_problem, CertificateFacts,
    FieldOptions,
};
use crate::x509::keys::pem_to_der;

/// A certificate as a caller holds it: PEM text (parsed as node's
/// `X509Certificate` parses a string) or DER.
#[derive(Clone, Copy, Debug)]
pub enum CertificateInput<'a> {
    Pem(&'a str),
    Der(&'a [u8]),
}

impl CertificateInput<'_> {
    fn der(&self) -> Option<Vec<u8>> {
        match self {
            CertificateInput::Der(d) => Some(d.to_vec()),
            CertificateInput::Pem(p) => pem_to_der(p).ok(),
        }
    }
}

/// A refusal: `{ code, role, why }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorProblem {
    pub code: ErrorCode,
    /// The role the certificate was held to; empty when it is not one.
    pub role: String,
    pub why: String,
}

/// `anchorProblem()`'s options.
#[derive(Clone, Debug, Default)]
pub struct AnchorOptions<'a> {
    /// `anchor` or `intermediate`; `None`: a self-issued certificate is an
    /// anchor, any other an intermediate.
    pub role: Option<&'a str>,
    /// The anchors an intermediate may chain to.
    pub held_anchors: Vec<CertificateInput<'a>>,
    /// Intermediates held beside them (the asynchronous door only).
    pub held_intermediates: Vec<Vec<u8>>,
    /// Milliseconds since the epoch; `None` is the wall clock.
    pub now_ms: Option<i64>,
}

struct Read {
    entry: Entry,
    facts: CertificateFacts,
    role: String,
}

/// `anchorFieldsOf()`: the certificate read, its role, and the first field
/// rule it breaks.
fn anchor_fields_of(
    cert: CertificateInput<'_>,
    opts: &AnchorOptions<'_>,
) -> Result<Read, AnchorProblem> {
    let entry = cert.der().and_then(|d| Entry::from_der(&d));
    let facts = entry.as_ref().and_then(|e| certificate_facts(&e.der).ok());
    let (Some(entry), Some(facts)) = (entry, facts) else {
        return Err(AnchorProblem {
            code: codes::STS_PKI_0238,
            role: opts.role.unwrap_or_default().to_string(),
            why: "this is not an X.509 certificate".to_string(),
        });
    };
    let role = opts.role.map(str::to_string).unwrap_or_else(|| {
        if facts.self_issued {
            "anchor"
        } else {
            "intermediate"
        }
        .to_string()
    });
    let refuse = |code: ErrorCode, why: String| AnchorProblem {
        code,
        role: role.clone(),
        why,
    };
    if !facts.ca {
        return Err(refuse(
            codes::STS_PKI_0234,
            format!(
                "\"{}\" is a leaf, not a certificate authority: a leaf to pin goes on the entry or relationship that uses it, never in a truststore",
                facts.subject
            ),
        ));
    }
    if role == "anchor" && !facts.self_issued {
        return Err(refuse(
            codes::STS_PKI_0228,
            format!(
                "\"{}\" is not self-signed, so it cannot be an anchor; add the Root it chains to, and this as an intermediate",
                facts.subject
            ),
        ));
    }
    let asked = FieldOptions {
        role: Some(role.clone()),
        key_usage: vec!["keyCertSign".to_string()],
        now_ms: opts.now_ms,
        ..FieldOptions::default()
    };
    if let Ok(Some(field)) = certificate_field_problem(&entry.der, &asked) {
        let code = match field.check {
            "validity" => codes::STS_PKI_0231,
            "basic-constraints" => codes::STS_PKI_0229,
            "key-usage" => codes::STS_PKI_0230,
            _ => codes::STS_PKI_0232,
        };
        return Err(refuse(code, field.why));
    }
    Ok(Read { entry, facts, role })
}

fn now_of(opts: &AnchorOptions<'_>) -> i64 {
    opts.now_ms.unwrap_or_else(|| Utc::now().timestamp_millis())
}

/// `anchorProblem()`: holds a certificate to a truststore's admission rule.
/// An intermediate must build a path, through the held intermediates, to a
/// held anchor.
#[tracing::instrument(level = "debug", skip_all)]
pub fn anchor_problem(
    cert: CertificateInput<'_>,
    opts: &AnchorOptions<'_>,
) -> Option<AnchorProblem> {
    let read = match anchor_fields_of(cert, opts) {
        Ok(r) => r,
        Err(p) => return Some(p),
    };
    if read.role == "anchor" && !path_signed(&read.entry, &read.entry) {
        return Some(AnchorProblem {
            code: codes::STS_PKI_0228,
            role: read.role,
            why: format!(
                "\"{}\" does not verify under its own key",
                read.facts.subject
            ),
        });
    }
    if read.role == "intermediate" {
        let held: Vec<Entry> = opts
            .held_anchors
            .iter()
            .filter_map(|one| one.der().and_then(|d| Entry::from_der(&d)))
            .collect();
        let path = verify_path_to_anchors(
            &read.entry.der,
            &opts.held_intermediates,
            &held,
            &PathOptions {
                now_ms: now_of(opts),
                ..PathOptions::default()
            },
        );
        if !path.ok {
            return Some(AnchorProblem {
                code: codes::STS_PKI_0233,
                role: read.role,
                why: format!(
                    "\"{}\" chains to no anchor held here ({})",
                    read.facts.subject, path.reason
                ),
            });
        }
    }
    None
}

/// `anchorProblemSync()`: the same rule for the client-certificate
/// truststore's synchronous doors. The self-signature is OpenSSL's to
/// verify — a key it cannot read (a composite) passes on its fields alone,
/// as in Node — and an intermediate is asked one hop.
#[tracing::instrument(level = "debug", skip_all)]
pub fn anchor_problem_sync(
    cert: CertificateInput<'_>,
    opts: &AnchorOptions<'_>,
) -> Option<AnchorProblem> {
    let read = match anchor_fields_of(cert, opts) {
        Ok(r) => r,
        Err(p) => return Some(p),
    };
    if read.role == "anchor" {
        // node's `x509.verify(x509.publicKey)`: the getter throws for a key
        // OpenSSL cannot read, which Node catches and lets pass; a failed
        // verification is false.
        let signed = match read.entry.x509.public_key() {
            Ok(key) => read.entry.x509.verify(&key).unwrap_or(false),
            Err(_) => true,
        };
        if !signed {
            return Some(AnchorProblem {
                code: codes::STS_PKI_0228,
                role: read.role,
                why: format!(
                    "\"{}\" does not verify under its own key",
                    read.facts.subject
                ),
            });
        }
        return None;
    }
    let held: Vec<Vec<u8>> = opts
        .held_anchors
        .iter()
        .filter_map(|one| one.der())
        .collect();
    let (direct, _) = verify_issued_directly(
        &read.entry.der,
        &held,
        &PathOptions {
            now_ms: now_of(opts),
            ..PathOptions::default()
        },
    );
    if !direct.ok {
        return Some(AnchorProblem {
            code: codes::STS_PKI_0233,
            role: read.role,
            why: format!(
                "\"{}\" chains to nothing held here ({})",
                read.facts.subject, direct.reason
            ),
        });
    }
    None
}
