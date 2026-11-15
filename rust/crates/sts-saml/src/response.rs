// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE `<samlp:Response>` (`saml2_sso.ts`'s `statusElement()` and
//! `buildResponse()`): one builder for the success and the failure alike,
//! because the two differ by one child and a status code, every attribute
//! and child in the model's order (#1579), signed after its `<Issuer>`
//! where `saml2.signResponse` holds for the service provider. A signing
//! failure answers the Response unsigned (STS-SAML-0013), as Node does.

use sts_crypto::xmldsig::Placement;

use crate::assertion::XmlSigner;
use crate::model::{self, escape};

/// `statusElement(code, subCode, message)`.
#[tracing::instrument(level = "debug")]
pub fn status_element(code: &str, sub_code: &str, message: &str) -> String {
    let sub = if sub_code.is_empty() {
        String::new()
    } else {
        format!(
            "<samlp:StatusCode{}/>",
            model::attributes("saml2.StatusCode", &[("value", sub_code)])
        )
    };
    let status_code = format!(
        "<samlp:StatusCode{}>{}</samlp:StatusCode>",
        model::attributes("saml2.StatusCode", &[("value", code)]),
        model::children("saml2.StatusCode", &[("statusCode", &sub)])
    );
    let msg = if message.is_empty() {
        String::new()
    } else {
        format!(
            "<samlp:StatusMessage>{}</samlp:StatusMessage>",
            escape(message)
        )
    };
    format!(
        "<samlp:Status>{}</samlp:Status>",
        model::children(
            "saml2.Status",
            &[("statusCode", &status_code), ("statusMessage", &msg)]
        )
    )
}

/// `buildResponse(opts)`'s options, the ID and instant handed in.
#[derive(Clone, Debug, Default)]
pub struct ResponseOptions {
    pub id: String,
    pub issue_instant: String,
    pub destination: String,
    pub in_response_to: String,
    /// This identity provider's entityID.
    pub issuer: String,
    pub status: String,
    pub sub_status: String,
    pub status_message: String,
    /// The assertion's XML (an `<saml:EncryptedAssertion>` too), or empty.
    pub assertion: String,
}

/// What [`build_response`] made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltResponse {
    pub xml: String,
    pub id: String,
    pub signed: bool,
}

/// The Response's XML, unsigned.
#[tracing::instrument(level = "debug", skip_all)]
pub fn response_xml(o: &ResponseOptions) -> String {
    format!(
        "<samlp:Response xmlns:samlp=\"{}\" xmlns:saml=\"{}\"{}>{}\
         </samlp:Response>",
        model::ns::samlp(),
        model::ns::saml(),
        model::attributes(
            "saml2.Response",
            &[
                ("id", &o.id),
                ("issueInstant", &o.issue_instant),
                ("destination", &o.destination),
                ("inResponseTo", &o.in_response_to),
            ]
        ),
        model::children(
            "saml2.Response",
            &[
                (
                    "issuer",
                    &format!(
                        "<saml:Issuer>{}</saml:Issuer>",
                        escape(&o.issuer)
                    )
                ),
                (
                    "status",
                    &status_element(
                        &o.status,
                        &o.sub_status,
                        &o.status_message
                    )
                ),
                ("assertion", &o.assertion),
            ]
        )
    )
}

/// `buildResponse(opts)`: signed with `signer` (after the `<Issuer>`) when
/// one is given — the caller's `settingFor(sp, 'saml2.signResponse')`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build_response(
    o: &ResponseOptions,
    signer: Option<&XmlSigner>,
) -> BuiltResponse {
    let xml = response_xml(o);
    let Some(signer) = signer else {
        return BuiltResponse {
            xml,
            id: o.id.clone(),
            signed: false,
        };
    };
    match signer.sign(&xml, Placement::AfterIssuer) {
        Ok(signed) => BuiltResponse {
            xml: signed,
            id: o.id.clone(),
            signed: true,
        },
        Err(e) => {
            tracing::error!(
                "{}the SAML 2.0 Response could not be signed, sending it \
                 unsigned: {}",
                sts_core::log::tag(
                    sts_core::errors::codes::STS_SAML_0013.as_str()
                ),
                e
            );
            BuiltResponse {
                xml,
                id: o.id.clone(),
                signed: false,
            }
        }
    }
}

/// `soapEnvelope(inner)`: the SOAP 1.1 envelope the back channel answers.
#[tracing::instrument(level = "debug", skip_all)]
pub fn soap_envelope(inner: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope \
         xmlns:soap=\"{}\"><soap:Body>{}</soap:Body></soap:Envelope>",
        model::term("saml2.namespace", "soap"),
        inner
    )
}

/// `buildArtifactResponse(idp, inResponseTo, status, message, payload)`:
/// DELIBERATELY NOT SIGNED — what a service provider verifies is the
/// Response inside, with its own signatures; the back channel's integrity
/// is TLS's.
#[tracing::instrument(level = "debug", skip_all)]
pub fn artifact_response(
    id: &str,
    issue_instant: &str,
    idp_entity_id: &str,
    in_response_to: &str,
    status: &str,
    status_message: &str,
    payload: &str,
) -> String {
    format!(
        "<samlp:ArtifactResponse xmlns:samlp=\"{}\" xmlns:saml=\"{}\"{}>{}\
         </samlp:ArtifactResponse>",
        model::ns::samlp(),
        model::ns::saml(),
        model::attributes(
            "saml2.ArtifactResponse",
            &[
                ("id", id),
                ("issueInstant", issue_instant),
                ("inResponseTo", in_response_to)
            ]
        ),
        model::children(
            "saml2.ArtifactResponse",
            &[
                (
                    "issuer",
                    &format!(
                        "<saml:Issuer>{}</saml:Issuer>",
                        escape(idp_entity_id)
                    )
                ),
                ("status", &status_element(status, "", status_message)),
                ("message", payload),
            ]
        )
    )
}

fn signed_or_not(
    xml: String,
    id: &str,
    signer: Option<&XmlSigner>,
    what: &str,
) -> String {
    let Some(signer) = signer else {
        return xml;
    };
    match signer.sign_referenced(
        &xml,
        Placement::AfterIssuer,
        &format!("#{}", id),
    ) {
        Ok(signed) => signed,
        Err(e) => {
            tracing::error!(
                "{}the {} could not be signed, sending it unsigned: {}",
                sts_core::log::tag(
                    sts_core::errors::codes::STS_SAML_0013.as_str()
                ),
                what,
                e
            );
            xml
        }
    }
}

/// `buildLogoutResponse(idp, destination, inResponseTo, status, message,
/// sp, subStatus)`: signed where `saml2.signResponse` holds for the service
/// provider (`signer`).
#[allow(clippy::too_many_arguments)] // Node's arguments, one each
#[tracing::instrument(level = "debug", skip_all)]
pub fn logout_response(
    id: &str,
    issue_instant: &str,
    idp_entity_id: &str,
    destination: &str,
    in_response_to: &str,
    status: &str,
    message: &str,
    sub_status: &str,
    signer: Option<&XmlSigner>,
) -> String {
    let xml = format!(
        "<samlp:LogoutResponse xmlns:samlp=\"{}\" xmlns:saml=\"{}\"{}>{}\
         </samlp:LogoutResponse>",
        model::ns::samlp(),
        model::ns::saml(),
        model::attributes(
            "saml2.LogoutResponse",
            &[
                ("id", id),
                ("issueInstant", issue_instant),
                ("destination", destination),
                ("inResponseTo", in_response_to)
            ]
        ),
        model::children(
            "saml2.LogoutResponse",
            &[
                (
                    "issuer",
                    &format!(
                        "<saml:Issuer>{}</saml:Issuer>",
                        escape(idp_entity_id)
                    )
                ),
                ("status", &status_element(status, sub_status, message)),
            ]
        )
    );
    signed_or_not(xml, id, signer, "LogoutResponse")
}

/// `subjectFor(sp, nameId, format)` in the clear: the `<saml:NameID>` of a
/// LogoutRequest (the encrypted form is the caller's, `encryptFor()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn logout_name_id(name_id: &str, format: &str) -> String {
    format!(
        "<saml:NameID{}>{}</saml:NameID>",
        if format.is_empty() {
            String::new()
        } else {
            format!(" Format=\"{}\"", escape(format))
        },
        escape(name_id)
    )
}

/// `buildLogoutRequest(idp, destination, nameId, format, sessionIndex,
/// sp)`, with the subject element already made ([`logout_name_id`], or an
/// `<saml:EncryptedID>`).
#[allow(clippy::too_many_arguments)] // Node's arguments, one each
#[tracing::instrument(level = "debug", skip_all)]
pub fn logout_request(
    id: &str,
    issue_instant: &str,
    idp_entity_id: &str,
    destination: &str,
    subject: &str,
    session_index: &str,
    signer: Option<&XmlSigner>,
) -> String {
    let index = if session_index.is_empty() {
        String::new()
    } else {
        format!(
            "<samlp:SessionIndex>{}</samlp:SessionIndex>",
            escape(session_index)
        )
    };
    let xml = format!(
        "<samlp:LogoutRequest xmlns:samlp=\"{}\" xmlns:saml=\"{}\"{}>{}\
         </samlp:LogoutRequest>",
        model::ns::samlp(),
        model::ns::saml(),
        model::attributes(
            "saml2.LogoutRequest",
            &[
                ("id", id),
                ("issueInstant", issue_instant),
                ("destination", destination)
            ]
        ),
        model::children(
            "saml2.LogoutRequest",
            &[
                (
                    "issuer",
                    &format!(
                        "<saml:Issuer>{}</saml:Issuer>",
                        escape(idp_entity_id)
                    )
                ),
                ("nameId", subject),
                ("sessionIndex", &index),
            ]
        )
    );
    signed_or_not(xml, id, signer, "LogoutRequest")
}
