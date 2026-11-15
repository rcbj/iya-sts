// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE IDENTITY PROVIDER'S METADATA (`saml2_sso.ts`'s `metadataFor()`,
//! `algorithmSupport()`, `endpointsFor()`; `document_settings.ts`'s
//! `organizationElement()`): ONE ENTITY, ONE DOCUMENT (#523) — SAML 2.0's
//! IdP and attribute authority roles with SAML 1.1's fragments joined in,
//! WS-Federation's role in its own view only (#524), every descriptor in the
//! model's order (#1579), signed with the realm's XML key, the signature
//! first. A signing failure serves it unsigned (STS-SAML-0014), as Node does.
//!
//! WHAT A CALLER HANDS IN ([`MetadataInputs`]): the parts other modules own
//! — the XML signing and encryption certificates with their chains
//! (`helpers.ownXmlSigningCertificates()`, `ownXmlEncryptionCertificates()`),
//! the back channel's TLS KeyDescriptors (`listener_keys.ts`), SAML 1.1's
//! `metadataParts()`, WS-Federation's role, the other listeners' bases
//! (`listener_map.alternatives('saml2')`) and the algorithms the realm's
//! policy publishes — and the document's ID.

use sts_crypto::xmldsig::Placement;

use crate::assertion::{x509_data_xml, XmlSigner};
use crate::model::{self, escape};

/// `BASE_PATH` and the endpoints under it.
pub const BASE_PATH: &str = "/saml2";
pub const METADATA_PATH: &str = "/saml2/metadata";

/// `endpointsFor(base, sp)`: one place for every URL, so the metadata and
/// the handlers cannot disagree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoints {
    pub sso: String,
    pub slo: String,
    pub ars: String,
    pub aa: String,
    pub unsolicited: String,
    pub metadata: String,
}

/// `endpointsFor(base, spEntityId)`; `slug` is `slugOf(sp)`, empty for the
/// unscoped document.
#[tracing::instrument(level = "debug")]
pub fn endpoints_for(base: &str, slug: &str) -> Endpoints {
    let suffix = if slug.is_empty() {
        String::new()
    } else {
        format!("/{}", crate::binding::encode_uri_component(slug))
    };
    let at = |p: &str| format!("{}{}/{}{}", base, BASE_PATH, p, suffix);
    Endpoints {
        sso: at("sso"),
        slo: at("slo"),
        ars: at("ars"),
        aa: at("aa"),
        unsolicited: at("unsolicited"),
        metadata: at("metadata"),
    }
}

/// `organizationElement(base)`: `<md:Organization>`, or '' when the name
/// or the display name is empty; the URL is the base's root when unset.
#[tracing::instrument(level = "debug", skip_all)]
pub fn organization_element(
    name: &str,
    display: &str,
    url: &str,
    base: &str,
) -> String {
    let (name, display, url) = (name.trim(), display.trim(), url.trim());
    if name.is_empty() || display.is_empty() {
        return String::new();
    }
    let url = if url.is_empty() {
        format!("{}/", base)
    } else {
        url.to_string()
    };
    format!(
        "<md:Organization><md:OrganizationName xml:lang=\"en\">{}\
         </md:OrganizationName><md:OrganizationDisplayName xml:lang=\"en\">{}\
         </md:OrganizationDisplayName><md:OrganizationURL xml:lang=\"en\">{}\
         </md:OrganizationURL></md:Organization>",
        escape(name),
        escape(display),
        escape(&url)
    )
}

/// `algorithmSupport()`: the Algorithm Support profile's elements, the
/// digests first and then the signing methods, as the policy publishes
/// them; '' with `saml2.publishAlgorithmSupport` off.
#[tracing::instrument(level = "debug", skip_all)]
pub fn algorithm_support(digests: &[String], signing: &[String]) -> String {
    let ns = model::term("saml2.namespace", "algorithmSupport");
    let element = |name: &str, uri: &str| {
        format!(
            "<alg:{} xmlns:alg=\"{}\" Algorithm=\"{}\"/>",
            name,
            ns,
            escape(uri)
        )
    };
    digests
        .iter()
        .map(|d| element("DigestMethod", d))
        .chain(signing.iter().map(|s| element("SigningMethod", s)))
        .collect()
}

/// A certificate this document publishes, with its chain.
#[derive(Clone, Debug, Default)]
pub struct Published {
    pub cert_pem: String,
    pub chain_pem: Vec<String>,
}

/// SAML 1.1's `metadataParts(base, sp)`: its fragments of each role.
#[derive(Clone, Debug, Default)]
pub struct Saml11Parts {
    pub name_id_formats: Vec<String>,
    pub sso_protocols: Vec<String>,
    pub aa_protocols: Vec<String>,
    pub artifact_resolution: String,
    pub single_sign_on: String,
    pub attribute_service: String,
}

/// What [`metadata_for`] is built from.
#[derive(Clone, Debug, Default)]
pub struct MetadataInputs {
    pub id: String,
    pub idp_entity_id: String,
    pub base: String,
    pub endpoints: Endpoints,
    /// One per live generation of the XML signing key (#42).
    pub signing: Vec<Published>,
    /// The current XML key, or a pinned one (#263).
    pub encryption: Vec<Published>,
    /// `listenerKeys.keyDescriptors()` (#248).
    pub back_channel_keys: String,
    pub saml11: Saml11Parts,
    /// WS-Federation's role, in its view only (#524).
    pub wsfed_role: String,
    /// The other listeners' bases with the realm's prefix (#472).
    pub elsewhere: Vec<String>,
    pub want_authn_requests_signed: bool,
    /// `helpers.rebaseTo(base, 'pki')`.
    pub pki_base: String,
    /// [`algorithm_support`]'s elements.
    pub algorithm_support: String,
    /// [`organization_element`].
    pub organization: String,
}

fn service(
    element: &str,
    binding: &str,
    location: &str,
    extra: &str,
) -> String {
    format!(
        "<md:{} Binding=\"{}\" Location=\"{}\"{}/>",
        element,
        binding,
        escape(location),
        extra
    )
}

fn key_descriptors(use_: &str, list: &[Published]) -> String {
    list.iter()
        .map(|p| {
            format!(
                "<md:KeyDescriptor use=\"{}\"><ds:KeyInfo xmlns:ds=\"{}\">{}\
                 </ds:KeyInfo></md:KeyDescriptor>",
                use_,
                model::term("saml2.namespace", "xmlSignature"),
                x509_data_xml(&p.cert_pem, &p.chain_pem)
            )
        })
        .collect()
}

/// The unsigned document `metadataFor()` signs.
#[tracing::instrument(level = "debug", skip_all)]
pub fn metadata_xml(i: &MetadataInputs) -> String {
    let redirect = model::term("saml2.binding", "redirect");
    let post = model::term("saml2.binding", "post");
    let simple = model::term("saml2.binding", "simpleSign");
    let soap = model::term("saml2.binding", "soap");
    let samlp = model::ns::samlp();
    let mut name_id_formats: Vec<String> =
        model::terms("saml2.nameIdFormat", Some("advertised"))
            .into_iter()
            .map(String::from)
            .collect();
    for f in &i.saml11.name_id_formats {
        if !name_id_formats.contains(f) {
            name_id_formats.push(f.clone());
        }
    }
    let also_at = |element: &str, location: &str| -> String {
        i.elsewhere
            .iter()
            .map(|to| {
                let moved = match location.strip_prefix(i.base.as_str()) {
                    Some(rest) => format!("{}{}", to, rest),
                    None => location.to_string(),
                };
                format!(
                    "{}{}{}",
                    service(element, redirect, &moved, ""),
                    service(element, post, &moved, ""),
                    service(element, simple, &moved, "")
                )
            })
            .collect()
    };
    let name_id_els: String = name_id_formats
        .iter()
        .map(|f| format!("<md:NameIDFormat>{}</md:NameIDFormat>", f))
        .collect();
    let signing = key_descriptors("signing", &i.signing);
    let protocols = |extra: &[String]| -> String {
        std::iter::once(samlp.to_string())
            .chain(extra.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let idp = format!(
        "<md:IDPSSODescriptor{}>{}</md:IDPSSODescriptor>",
        model::attributes(
            "md.IDPSSODescriptor",
            &[
                (
                    "wantAuthnRequestsSigned",
                    if i.want_authn_requests_signed {
                        "true"
                    } else {
                        "false"
                    }
                ),
                (
                    "protocolSupportEnumeration",
                    &protocols(&i.saml11.sso_protocols)
                ),
            ]
        ),
        model::children(
            "md.IDPSSODescriptor",
            &[
                (
                    "keyDescriptor",
                    &format!(
                        "{}{}{}",
                        signing,
                        key_descriptors("encryption", &i.encryption),
                        i.back_channel_keys
                    )
                ),
                (
                    "artifactResolutionService",
                    &format!(
                        "{}{}",
                        service(
                            "ArtifactResolutionService",
                            soap,
                            &i.endpoints.ars,
                            " index=\"0\" isDefault=\"true\""
                        ),
                        i.saml11.artifact_resolution
                    )
                ),
                (
                    "singleLogoutService",
                    &format!(
                        "{}{}{}{}",
                        service(
                            "SingleLogoutService",
                            redirect,
                            &i.endpoints.slo,
                            ""
                        ),
                        service(
                            "SingleLogoutService",
                            post,
                            &i.endpoints.slo,
                            ""
                        ),
                        service(
                            "SingleLogoutService",
                            simple,
                            &i.endpoints.slo,
                            ""
                        ),
                        also_at("SingleLogoutService", &i.endpoints.slo)
                    )
                ),
                ("nameIdFormat", &name_id_els),
                (
                    "singleSignOnService",
                    &format!(
                        "{}{}{}{}{}",
                        service(
                            "SingleSignOnService",
                            redirect,
                            &i.endpoints.sso,
                            ""
                        ),
                        service(
                            "SingleSignOnService",
                            post,
                            &i.endpoints.sso,
                            ""
                        ),
                        service(
                            "SingleSignOnService",
                            simple,
                            &i.endpoints.sso,
                            ""
                        ),
                        also_at("SingleSignOnService", &i.endpoints.sso),
                        i.saml11.single_sign_on
                    )
                ),
            ]
        )
    );
    let aa = format!(
        "<md:AttributeAuthorityDescriptor{}>{}</md:AttributeAuthorityDescriptor>",
        model::attributes(
            "md.AttributeAuthorityDescriptor",
            &[("protocolSupportEnumeration", &protocols(&i.saml11.aa_protocols))]
        ),
        model::children(
            "md.AttributeAuthorityDescriptor",
            &[
                (
                    "keyDescriptor",
                    &format!("{}{}", signing, i.back_channel_keys)
                ),
                (
                    "attributeService",
                    &format!(
                        "{}{}",
                        service("AttributeService", soap, &i.endpoints.aa, ""),
                        i.saml11.attribute_service
                    )
                ),
                ("nameIdFormat", &name_id_els),
            ]
        )
    );
    let extensions = format!(
        "<md:Extensions><cm:CryptoMetadataLocation \
         xmlns:cm=\"urn:iya:sts:crypto-metadata:1\">{}\
         </cm:CryptoMetadataLocation>{}</md:Extensions>",
        escape(&format!("{}/crypto/metadata.xml", i.pki_base)),
        i.algorithm_support
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor \
         xmlns:md=\"{}\"{}>{}</md:EntityDescriptor>",
        model::ns::md(),
        model::attributes(
            "md.EntityDescriptor",
            &[("id", &i.id), ("entityId", &i.idp_entity_id)]
        ),
        model::children(
            "md.EntityDescriptor",
            &[
                ("extensions", &extensions),
                ("roleDescriptor", &i.wsfed_role),
                ("idpSsoDescriptor", &idp),
                ("attributeAuthorityDescriptor", &aa),
                ("organization", &i.organization),
            ]
        )
    )
}

/// `metadataFor(base, sp, withWsFederation)`: signed first, or served
/// unsigned when it cannot be (STS-SAML-0014).
#[tracing::instrument(level = "debug", skip_all)]
pub fn metadata_for(i: &MetadataInputs, signer: &XmlSigner) -> String {
    let xml = metadata_xml(i);
    match signer.sign_referenced(&xml, Placement::First, &format!("#{}", i.id))
    {
        Ok(signed) => signed,
        Err(e) => {
            tracing::error!(
                "{}the SAML 2.0 metadata could not be signed, serving it \
                 unsigned: {}",
                sts_core::log::tag(
                    sts_core::errors::codes::STS_SAML_0014.as_str()
                ),
                e
            );
            xml
        }
    }
}

/// SAML 1.1's `metadataParts(base, rp)` (`saml11_sso.ts`): its roles'
/// fragments of the one document, scoped to the same slug — the
/// responder as the ArtifactResolutionService at index 1 and as the
/// AttributeService, the two browser profiles and Shibboleth's request
/// profile as SingleSignOnServices, and no SingleLogoutService (SAML 1.1
/// has none).
#[tracing::instrument(level = "debug")]
pub fn saml11_parts(base: &str, slug: &str) -> Saml11Parts {
    let suffix = if slug.is_empty() {
        String::new()
    } else {
        format!("/{}", crate::binding::encode_uri_component(slug))
    };
    let sso = format!("{}/saml11/sso{}", base, suffix);
    let responder = format!("{}/saml11/responder{}", base, suffix);
    let soap = model::term("saml11.binding", "soap");
    Saml11Parts {
        name_id_formats: model::terms(
            "saml11.nameIdFormat",
            Some("advertised"),
        )
        .into_iter()
        .map(String::from)
        .collect(),
        sso_protocols: vec![
            model::term("saml11.protocol", "saml11").to_string(),
            model::term("saml11.protocol", "shibboleth1").to_string(),
        ],
        aa_protocols: vec![model::term("saml11.protocol", "saml11").to_string()],
        artifact_resolution: service(
            "ArtifactResolutionService",
            soap,
            &responder,
            " index=\"1\"",
        ),
        single_sign_on: format!(
            "{}{}{}",
            service(
                "SingleSignOnService",
                model::term("saml11.profile", "post"),
                &sso,
                ""
            ),
            service(
                "SingleSignOnService",
                model::term("saml11.profile", "artifact"),
                &sso,
                ""
            ),
            service(
                "SingleSignOnService",
                model::term("saml11.profile", "shibAuthnRequest"),
                &sso,
                ""
            )
        ),
        attribute_service: service("AttributeService", soap, &responder, ""),
    }
}
