// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SAML 2.0 ASSERTIONS (`saml/saml2.ts`'s `buildSamlAssertion()` and
//! `signAssertion()`): one builder for WS-Trust, WS-Federation and the Web
//! Browser SSO profile, every element in the model's order (#1579), and the
//! enveloped signature after the `<Issuer>`.
//!
//! WHAT A CALLER HANDS IN THAT NODE READS ITSELF:
//!
//! * the INSTANTS ([`Instants`]): Node reads `Date.now()` once per `iso()`
//!   call and `genId()` once; here they are worked out by
//!   [`Instants::at`] from one clock reading (the Conditions widened at both
//!   ends by `saml.clockSkewS`, as Node widens them), so a vector can hand in
//!   the ones Node wrote and get Node's bytes;
//! * the configured custom attributes (`stats.samlAttributes()`, the
//!   `/admin/saml-attributes` rows for this audience), APPENDED after the
//!   protocol's own and filtered against their names, as Node appends them;
//! * the SIGNER ([`XmlSigner`]): the realm's XML key for the configured
//!   algorithm (`STS.xmlSigner`), its KeyInfo (`helpers.xmlSignerKeyInfo()`,
//!   [`x509_data_xml`]) and the realm's signature policy.
//!
//! What it does not do: count the assertion in `/admin`'s register
//! (`stats.recordAssertion()`), which is the runtime's.

use chrono::{DateTime, SecondsFormat, Utc};
use sts_crypto::xmldsig::{self, EnvelopedOptions, Placement, XmlPolicy};

use crate::model::{self, escape};

/// `iso(offsetMin)` at a clock reading: `new Date(now + offsetMin * 60000)
/// .toISOString()`, the milliseconds truncated as `new Date()` truncates.
#[tracing::instrument(level = "debug")]
pub fn iso_at(now_ms: i64, offset_min: f64) -> String {
    let at = (now_ms as f64 + offset_min * 60000.0).trunc() as i64;
    DateTime::<Utc>::from_timestamp_millis(at)
        .map(|d| d.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_default()
}

/// `genId()`: `_` and 128 random bits in hex.
#[tracing::instrument(level = "debug")]
pub fn gen_id() -> String {
    let bytes = sts_crypto::random::random_bytes(16).unwrap_or_default();
    let mut s = String::from("_");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// The ID and the three instants an assertion carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Instants {
    pub id: String,
    /// `IssueInstant`, and the default `AuthnInstant`.
    pub now: String,
    /// `Conditions/@NotBefore`.
    pub not_before: String,
    /// `Conditions/@NotOnOrAfter`, and the confirmation's default expiry.
    pub not_on_or_after: String,
}

impl Instants {
    /// Node's three `iso()` calls at one clock reading: `now`, `now - skew`,
    /// `now + lifetime + skew` (a lifetime of 0 or less is 60 minutes).
    #[tracing::instrument(level = "debug")]
    pub fn at(
        now_ms: i64,
        lifetime_min: f64,
        skew_s: f64,
        id: String,
    ) -> Instants {
        let skew = skew_s.max(0.0);
        let lifetime = if lifetime_min > 0.0 {
            lifetime_min
        } else {
            60.0
        };
        Instants {
            id,
            now: iso_at(now_ms, 0.0),
            not_before: iso_at(now_ms, -skew / 60.0),
            not_on_or_after: iso_at(now_ms, lifetime + skew / 60.0),
        }
    }
}

/// One `<saml:Attribute>`: a SAML attribute is MULTI-VALUED.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttributeRow {
    pub name: String,
    pub name_format: String,
    /// The X.500/LDAP profile's LDAP name beside an OID `Name` (#189).
    pub friendly_name: String,
    pub values: Vec<String>,
}

impl AttributeRow {
    /// One name, one value.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn one(name: &str, value: &str) -> AttributeRow {
        AttributeRow {
            name: name.to_string(),
            values: vec![value.to_string()],
            ..AttributeRow::default()
        }
    }
}

/// A party that ACTED for the subject (#186), least to most recent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delegate {
    pub name_id: String,
    pub format: String,
    pub instant: String,
}

/// The bearer confirmation's data (saml-profiles-2.0-os 4.1.4.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectConfirmation {
    pub recipient: String,
    pub in_response_to: String,
    /// Empty: the Conditions instant, the same string.
    pub not_on_or_after: String,
}

/// `buildSamlAssertion()`'s options.
#[derive(Clone, Debug, Default)]
pub struct AssertionOptions {
    pub authn_context_class_ref: String,
    /// Replacing the default two (`name`, `issuedBy`) when not empty.
    pub attributes: Vec<AttributeRow>,
    /// The configured ones, appended and filtered against the above.
    pub custom: Vec<AttributeRow>,
    pub name_id_format: String,
    pub name_id_value: Option<String>,
    pub subject_confirmation: Option<SubjectConfirmation>,
    pub session_index: String,
    pub authn_instant: String,
    /// Who signed it: the realm's issuer at the request's base (#523).
    pub issuer: String,
    pub attribute_query: bool,
    pub name_qualifier: String,
    pub sp_name_qualifier: String,
    pub delegates: Vec<Delegate>,
}

/// The realm's XML signer, as `signAssertion()` and `signDocument()` read
/// it.
#[derive(Clone, Debug)]
pub struct XmlSigner {
    pub private_key_pem: String,
    pub cert_pem: String,
    /// The chain beside the certificate, leaf excluded (`certChainPem`).
    pub chain_pem: Vec<String>,
    /// `documentSettings.signatureOptions()`.
    pub sig_alg: String,
    pub c14n_alg: String,
    pub policy: XmlPolicy,
}

/// `stsCrypto.stripPem()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn strip_pem(pem: &str) -> String {
    let mut out = String::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 5..];
        match after.find("-----") {
            Some(end) if !after[..end].contains('-') => {
                rest = &after[end + 5..];
            }
            _ => {
                out.push_str("-----");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out.chars().filter(|c| !c.is_whitespace()).collect()
}

/// `helpers.x509DataXml()`: the certificate first, then the chain as given
/// (`pki.chainThroughRoot()`'s answer), and the signer's certificate again
/// after a chain whose last member is not it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn x509_data_xml(cert_pem: &str, chain: &[String]) -> String {
    let mut members: Vec<String> = std::iter::once(cert_pem)
        .chain(chain.iter().map(String::as_str))
        .map(strip_pem)
        .collect();
    if members.len() > 1 && members.last() != members.first() {
        members.push(members[0].clone());
    }
    let mut out = String::from("<ds:X509Data>");
    for b64 in members {
        out.push_str(&format!(
            "<ds:X509Certificate>{}</ds:X509Certificate>",
            b64
        ));
    }
    out.push_str("</ds:X509Data>");
    out
}

impl XmlSigner {
    /// `crypto.signXml()` with the realm's key: an enveloped signature over
    /// the root, at `placement`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign(
        &self,
        xml: &str,
        placement: Placement,
    ) -> Result<String, String> {
        let key = sts_crypto::keys::private_key_from_pem(&self.private_key_pem)
            .map_err(|e| e.to_string())?;
        let key_info = x509_data_xml(&self.cert_pem, &self.chain_pem);
        xmldsig::sign_enveloped(
            xml,
            &key,
            &EnvelopedOptions {
                sig_alg: Some(self.sig_alg.as_str()).filter(|s| !s.is_empty()),
                c14n_alg: Some(self.c14n_alg.as_str())
                    .filter(|s| !s.is_empty()),
                placement,
                cert_pem: Some(&self.cert_pem),
                key_info_xml: Some(&key_info),
                policy: self.policy.clone(),
                ..EnvelopedOptions::default()
            },
        )
        .map_err(|e| e.to_string())
    }
}

fn values_of(a: &AttributeRow) -> String {
    a.values
        .iter()
        .map(|v| {
            format!("<saml:AttributeValue>{}</saml:AttributeValue>", escape(v))
        })
        .collect()
}

/// `buildSamlAssertion(subject, audience, lifetimeMin, opts)` with the
/// signature left to the caller: the assertion's XML, unsigned.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build_unsigned(
    subject: &str,
    audience: &str,
    at: &Instants,
    o: &AssertionOptions,
) -> String {
    let audience_el = if audience.is_empty() {
        String::new()
    } else {
        format!(
            "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
             </saml:AudienceRestriction>",
            escape(audience)
        )
    };
    let delegation_el = if o.delegates.is_empty() {
        String::new()
    } else {
        let mut s = format!(
            "<saml:Condition xmlns:xsi=\"http://www.w3.org/2001/\
             XMLSchema-instance\" xmlns:del=\"{}\" xsi:type=\"{}\">",
            model::term("saml2.condition", "delegationNamespace"),
            model::term("saml2.condition", "delegationType")
        );
        for d in &o.delegates {
            let format = if d.format.is_empty() {
                model::term("saml2.nameIdFormat", "entity")
            } else {
                d.format.as_str()
            };
            s.push_str(&format!(
                "<del:Delegate{}><saml:NameID Format=\"{}\">{}</saml:NameID>\
                 </del:Delegate>",
                if d.instant.is_empty() {
                    String::new()
                } else {
                    format!(" DelegationInstant=\"{}\"", escape(&d.instant))
                },
                escape(format),
                escape(&d.name_id)
            ));
        }
        s.push_str("</saml:Condition>");
        s
    };
    let class_ref = if o.authn_context_class_ref.is_empty() {
        crate::authn_context::AC_UNSPECIFIED
    } else {
        o.authn_context_class_ref.as_str()
    };
    let issuer = o.issuer.as_str();
    let attributes: Vec<AttributeRow> = if o.attributes.is_empty() {
        vec![
            AttributeRow::one("name", subject),
            AttributeRow::one("issuedBy", issuer),
        ]
    } else {
        o.attributes.clone()
    };
    let names: Vec<&str> = attributes.iter().map(|a| a.name.as_str()).collect();
    let mut attribute_els = String::new();
    for a in attributes.iter().chain(
        o.custom
            .iter()
            .filter(|c| !names.contains(&c.name.as_str())),
    ) {
        attribute_els.push_str(&format!(
            "<saml:Attribute Name=\"{}\"{}{}>{}</saml:Attribute>",
            escape(&a.name),
            if a.name_format.is_empty() {
                String::new()
            } else {
                format!(" NameFormat=\"{}\"", escape(&a.name_format))
            },
            if a.friendly_name.is_empty() {
                String::new()
            } else {
                format!(" FriendlyName=\"{}\"", escape(&a.friendly_name))
            },
            values_of(a)
        ));
    }
    let name_id_format = if o.name_id_format.is_empty() {
        model::term("saml2.nameIdFormat", "unspecified")
    } else {
        o.name_id_format.as_str()
    };
    let name_id_value = o.name_id_value.as_deref().unwrap_or(subject);
    let bearer = model::term("saml2.confirmation", "bearer");
    let confirmation = match &o.subject_confirmation {
        Some(scd) => {
            let until = if scd.not_on_or_after.is_empty() {
                at.not_on_or_after.as_str()
            } else {
                scd.not_on_or_after.as_str()
            };
            format!(
                "<saml:SubjectConfirmation Method=\"{}\">\
                 <saml:SubjectConfirmationData{}/></saml:SubjectConfirmation>",
                bearer,
                model::attributes(
                    "saml2.SubjectConfirmationData",
                    &[
                        ("notOnOrAfter", until),
                        ("recipient", &scd.recipient),
                        ("inResponseTo", &scd.in_response_to),
                    ]
                )
            )
        }
        None => format!("<saml:SubjectConfirmation Method=\"{}\"/>", bearer),
    };
    let session_index = if o.session_index.is_empty() {
        at.id.as_str()
    } else {
        o.session_index.as_str()
    };
    let authn_instant = if o.authn_instant.is_empty() {
        at.now.as_str()
    } else {
        o.authn_instant.as_str()
    };
    let authn_statement = if o.attribute_query {
        String::new()
    } else {
        format!(
            "<saml:AuthnStatement{}>{}</saml:AuthnStatement>",
            model::attributes(
                "saml2.AuthnStatement",
                &[
                    ("authnInstant", authn_instant),
                    ("sessionIndex", session_index)
                ]
            ),
            model::children(
                "saml2.AuthnStatement",
                &[(
                    "authnContext",
                    &format!(
                        "<saml:AuthnContext><saml:AuthnContextClassRef>{}\
                         </saml:AuthnContextClassRef></saml:AuthnContext>",
                        escape(class_ref)
                    )
                )]
            )
        )
    };
    let name_id_el = format!(
        "<saml:NameID{}{} Format=\"{}\">{}</saml:NameID>",
        if o.name_qualifier.is_empty() {
            String::new()
        } else {
            format!(" NameQualifier=\"{}\"", escape(&o.name_qualifier))
        },
        if o.sp_name_qualifier.is_empty() {
            String::new()
        } else {
            format!(" SPNameQualifier=\"{}\"", escape(&o.sp_name_qualifier))
        },
        escape(name_id_format),
        escape(name_id_value)
    );
    let subject_el = format!(
        "<saml:Subject>{}</saml:Subject>",
        model::children(
            "saml2.Subject",
            &[
                ("nameId", &name_id_el),
                (
                    "subjectConfirmation",
                    if o.attribute_query { "" } else { &confirmation }
                ),
            ]
        )
    );
    let conditions = format!(
        "<saml:Conditions{}>{}</saml:Conditions>",
        model::attributes(
            "saml2.Conditions",
            &[
                ("notBefore", &at.not_before),
                ("notOnOrAfter", &at.not_on_or_after)
            ]
        ),
        model::children(
            "saml2.Conditions",
            &[
                ("condition", &delegation_el),
                ("audienceRestriction", &audience_el)
            ]
        )
    );
    format!(
        "<saml:Assertion xmlns:saml=\"{}\"{}>{}</saml:Assertion>",
        model::ns::saml(),
        model::attributes(
            "saml2.Assertion",
            &[("id", &at.id), ("issueInstant", &at.now)]
        ),
        model::children(
            "saml2.Assertion",
            &[
                (
                    "issuer",
                    &format!("<saml:Issuer>{}</saml:Issuer>", escape(issuer))
                ),
                ("subject", &subject_el),
                ("conditions", &conditions),
                ("authnStatement", &authn_statement),
                (
                    "attributeStatement",
                    &format!(
                        "<saml:AttributeStatement>{}</saml:AttributeStatement>",
                        attribute_els
                    )
                ),
            ]
        )
    )
}

/// What [`build`] made: the XML, and whether it is signed (a signing
/// failure answers the assertion unsigned, STS-SAML-0023, as Node does).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
    pub xml: String,
    pub signed: bool,
    pub id: String,
}

/// `buildSamlAssertion()`, signed after its `<Issuer>` unless `signer` is
/// `None` (`sign: false`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn build(
    subject: &str,
    audience: &str,
    at: &Instants,
    o: &AssertionOptions,
    signer: Option<&XmlSigner>,
) -> Built {
    let xml = build_unsigned(subject, audience, at, o);
    let Some(signer) = signer else {
        return Built {
            xml,
            signed: false,
            id: at.id.clone(),
        };
    };
    match signer.sign(&xml, Placement::AfterIssuer) {
        Ok(signed) => Built {
            xml: signed,
            signed: true,
            id: at.id.clone(),
        },
        Err(e) => {
            tracing::error!(
                "{}sign failed, returning unsigned: {}",
                sts_core::log::tag(
                    sts_core::errors::codes::STS_SAML_0023.as_str()
                ),
                e
            );
            Built {
                xml,
                signed: false,
                id: at.id.clone(),
            }
        }
    }
}

impl crate::binding::QuerySigner for XmlSigner {
    #[tracing::instrument(level = "debug", skip_all)]
    fn sig_alg(&self) -> String {
        self.sig_alg.clone()
    }

    /// `crypto.signQueryString()` with the realm's key.
    #[tracing::instrument(level = "debug", skip_all)]
    fn sign(&self, octets: &str, sig_alg: &str) -> Result<String, String> {
        let key = sts_crypto::keys::private_key_from_pem(&self.private_key_pem)
            .map_err(|e| e.to_string())?;
        xmldsig::sign_query_string(octets, &key, Some(sig_alg), &self.policy)
            .map_err(|e| e.to_string())
    }
}
