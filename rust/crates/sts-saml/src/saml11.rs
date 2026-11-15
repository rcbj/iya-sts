// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SAML 1.1 ASSERTIONS (`saml/saml11.ts`'s `buildSaml11Assertion()` and
//! `signSaml11Assertion()`): a separate profile, not SAML 2.0 with a version
//! flag (rule 4b). The AssertionID, the Issuer as an ATTRIBUTE, the
//! Conditions (widened by `saml.clockSkewS`, as [`crate::assertion`]
//! widens them), the AuthenticationStatement and the AttributeStatement
//! each carrying its own Subject, every element in the model's order, and
//! the enveloped signature LAST. A signing failure answers it unsigned
//! (STS-SAML-0024), as Node does.
//!
//! The instants and the custom attributes are the caller's, as for SAML
//! 2.0; a single cell's AssertionID carries no cell's tag (cells are phase
//! 9).

use sts_crypto::xmldsig::Placement;

use crate::assertion::{Instants, XmlSigner};
use crate::model::{self, escape};

/// One `<saml:Attribute>`: a name in a namespace, multi-valued.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attribute11 {
    pub name: String,
    pub namespace: String,
    pub values: Vec<String>,
}

/// `subjectLocality`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Locality {
    pub ip_address: String,
    pub dns_address: String,
}

/// `buildSaml11Assertion(opts)`'s options.
#[derive(Clone, Debug, Default)]
pub struct Options11 {
    pub subject: String,
    pub audience: String,
    pub issuer: String,
    pub authn_instant: String,
    pub authn_method: String,
    pub name_id_format: String,
    pub name_id_value: Option<String>,
    pub name_qualifier: String,
    pub confirmation_method: String,
    pub do_not_cache: bool,
    pub locality: Option<Locality>,
    pub attributes: Vec<Attribute11>,
    /// The configured ones (`stats.samlAttributes('saml11', …)`), appended
    /// and filtered against the asked ones by namespace and name.
    pub custom: Vec<Attribute11>,
    /// `authenticationStatement: false` leaves it out.
    pub without_authentication_statement: bool,
}

/// The assertion's XML, unsigned.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build_unsigned(at: &Instants, o: &Options11) -> String {
    let or = |v: &str, name: &str, id: &str| {
        if v.is_empty() {
            model::term(id, name).to_string()
        } else {
            v.to_string()
        }
    };
    let method = or(&o.authn_method, "unspecified", "saml11.authnMethod");
    let format = or(&o.name_id_format, "unspecified", "saml11.nameIdFormat");
    let confirmation =
        or(&o.confirmation_method, "bearer", "saml11.confirmation");
    let authn_instant = if o.authn_instant.is_empty() {
        at.now.as_str()
    } else {
        o.authn_instant.as_str()
    };
    let value = o.name_id_value.as_deref().unwrap_or(&o.subject);
    let qualifier = if o.name_qualifier.is_empty() {
        String::new()
    } else {
        format!(" NameQualifier=\"{}\"", escape(&o.name_qualifier))
    };
    let subject_el = format!(
        "<saml:Subject>{}</saml:Subject>",
        model::children(
            "saml11.Subject",
            &[
                (
                    "nameIdentifier",
                    &format!(
                        "<saml:NameIdentifier{} Format=\"{}\">{}\
                         </saml:NameIdentifier>",
                        qualifier,
                        escape(&format),
                        escape(value)
                    )
                ),
                (
                    "subjectConfirmation",
                    &format!(
                        "<saml:SubjectConfirmation><saml:ConfirmationMethod>{}\
                         </saml:ConfirmationMethod></saml:SubjectConfirmation>",
                        escape(&confirmation)
                    )
                ),
            ]
        )
    );
    let audience_el = if o.audience.is_empty() {
        String::new()
    } else {
        format!(
            "<saml:AudienceRestrictionCondition><saml:Audience>{}\
             </saml:Audience></saml:AudienceRestrictionCondition>",
            escape(&o.audience)
        )
    };
    let do_not_cache = if o.do_not_cache {
        "<saml:DoNotCacheCondition/>"
    } else {
        ""
    };
    let locality = match &o.locality {
        Some(l) if !l.ip_address.is_empty() || !l.dns_address.is_empty() => {
            format!(
                "<saml:SubjectLocality{}{}/>",
                if l.ip_address.is_empty() {
                    String::new()
                } else {
                    format!(" IPAddress=\"{}\"", escape(&l.ip_address))
                },
                if l.dns_address.is_empty() {
                    String::new()
                } else {
                    format!(" DNSAddress=\"{}\"", escape(&l.dns_address))
                }
            )
        }
        _ => String::new(),
    };
    let key = |a: &Attribute11| format!("{} {}", a.namespace, a.name);
    let asked: Vec<String> = o.attributes.iter().map(key).collect();
    let attribute_els: String = o
        .attributes
        .iter()
        .chain(o.custom.iter().filter(|c| !asked.contains(&key(c))))
        .map(|a| {
            format!(
                "<saml:Attribute AttributeName=\"{}\" \
                 AttributeNamespace=\"{}\">{}</saml:Attribute>",
                escape(&a.name),
                escape(&a.namespace),
                a.values
                    .iter()
                    .map(|v| format!(
                        "<saml:AttributeValue>{}</saml:AttributeValue>",
                        escape(v)
                    ))
                    .collect::<String>()
            )
        })
        .collect();
    let conditions = format!(
        "<saml:Conditions{}>{}</saml:Conditions>",
        model::attributes(
            "saml11.Conditions",
            &[
                ("notBefore", &at.not_before),
                ("notOnOrAfter", &at.not_on_or_after)
            ]
        ),
        model::children(
            "saml11.Conditions",
            &[
                ("audienceRestrictionCondition", &audience_el),
                ("doNotCacheCondition", do_not_cache)
            ]
        )
    );
    let authentication = if o.without_authentication_statement {
        String::new()
    } else {
        format!(
            "<saml:AuthenticationStatement{}>{}</saml:AuthenticationStatement>",
            model::attributes(
                "saml11.AuthenticationStatement",
                &[
                    ("authenticationMethod", &method),
                    ("authenticationInstant", authn_instant)
                ]
            ),
            model::children(
                "saml11.AuthenticationStatement",
                &[("subject", &subject_el), ("subjectLocality", &locality)]
            )
        )
    };
    let attribute_statement = if attribute_els.is_empty() {
        String::new()
    } else {
        format!(
            "<saml:AttributeStatement>{}</saml:AttributeStatement>",
            model::children(
                "saml11.AttributeStatement",
                &[("subject", &subject_el), ("attribute", &attribute_els)]
            )
        )
    };
    format!(
        "<saml:Assertion xmlns:saml=\"{}\"{}>{}</saml:Assertion>",
        model::term("saml11.namespace", "assertion"),
        model::attributes(
            "saml11.Assertion",
            &[
                ("assertionId", &at.id),
                ("issuer", &o.issuer),
                ("issueInstant", &at.now)
            ]
        ),
        model::children(
            "saml11.Assertion",
            &[
                ("conditions", &conditions),
                ("authenticationStatement", &authentication),
                ("attributeStatement", &attribute_statement),
            ]
        )
    )
}

/// `buildSaml11Assertion(opts)`: signed LAST unless `signer` is `None`
/// (`sign: false`); `(xml, signed)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build(
    at: &Instants,
    o: &Options11,
    signer: Option<&XmlSigner>,
) -> (String, bool) {
    let xml = build_unsigned(at, o);
    let Some(signer) = signer else {
        return (xml, false);
    };
    match signer.sign(&xml, Placement::Last) {
        Ok(signed) => (signed, true),
        Err(e) => {
            tracing::error!(
                "{}SAML 1.1 signing failed, returning the assertion \
                 unsigned: {}",
                sts_core::log::tag(
                    sts_core::errors::codes::STS_SAML_0024.as_str()
                ),
                e
            );
            (xml, false)
        }
    }
}
