// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `pki_revocation.js`'s OCSP responder (RFC 6960): `answerOcsp()`, one
//! responder per certificate authority, signed by that authority itself
//! (no delegated responder), its responder id BY KEY.
//!
//! * a CertID is the authority's when its name and key hashes are, in
//!   SHA-1, SHA-256, SHA-384 or SHA-512; another issuer's is `unknown`,
//!   and a request about nothing but another issuer is `unauthorized`;
//! * a serial on the list is `revoked` with its moment and (unless
//!   `unspecified`) its reason; one the register holds is `good`; one it
//!   does not is `unknown` — "not revoked" is not "issued here";
//! * a nonce of 1 to 32 octets is echoed, anything else is
//!   `malformedRequest`; a request that does not parse is too;
//! * `thisUpdate` is now and `nextUpdate` the CRL's lifetime later, and the
//!   response carries the authority's certificate.
//!
//! Written as pkijs writes it, so an RSA-signed answer to the same
//! request at the same moment is Node's byte for byte.

use chrono::{DateTime, Utc};
use openssl::hash::{hash, MessageDigest};
use openssl::sha::sha1;
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use super::catalog::scope_id;
use super::crl::{extension, spki_bits, status_signature_alg};
use super::hierarchy::{certificate_instant, ms_of, Authority};
use crate::der::{self, Element};
use crate::error::PkiResult;
use crate::x509::algorithms;
use crate::x509::issue::sign_bytes;
use crate::x509::keys::{pem_to_der, SigningKey};
use crate::x509::read::Certificate;
use crate::x509::time;

const NONCE_OID: &str = "1.3.6.1.5.5.7.48.1.2";
const BASIC_OID: &str = "1.3.6.1.5.5.7.48.1.1";

/// An answer: the DER and what it said.
#[derive(Debug, Clone, PartialEq)]
pub struct OcspAnswer {
    pub der: Vec<u8>,
    /// `successful`, `malformedRequest`, `internalError`, `unauthorized`.
    pub status: &'static str,
    /// The code an operator reads the refusal by, where there is one.
    pub code: Option<ErrorCode>,
    /// Per certificate asked about: `{ serial, status, why|reason }`.
    pub answers: Vec<Json>,
    pub this_update: String,
    pub next_update: String,
    pub nonce: bool,
}

/// `bareResponse()`: an OCSPResponse with a status and no body.
#[tracing::instrument(level = "debug")]
pub fn bare_response(status: i64) -> Vec<u8> {
    der::sequence(&[enumerated(status)])
}

fn enumerated(n: i64) -> Vec<u8> {
    let int = der::integer(n);
    der::tlv(0x0a, int.get(2..).unwrap_or_default())
}

/// asn1js's GeneralizedTime from a Date at whole seconds.
fn generalized(t: &DateTime<Utc>) -> Vec<u8> {
    der::tlv(
        der::GENERALIZED_TIME,
        t.format("%Y%m%d%H%M%SZ").to_string().as_bytes(),
    )
}

fn refused(status: i64, name: &'static str, code: ErrorCode) -> OcspAnswer {
    OcspAnswer {
        der: bare_response(status),
        status: name,
        code: Some(code),
        answers: Vec::new(),
        this_update: String::new(),
        next_update: String::new(),
        nonce: false,
    }
}

/// One Request of a request list.
struct Asked<'a> {
    cert_id: Element<'a>,
    hash: Option<MessageDigest>,
    name_hash: &'a [u8],
    key_hash: &'a [u8],
    serial: String,
}

/// `pkijs.OCSPRequest.fromBER()`: the request list and the nonce, or
/// `None` for anything that is not an OCSPRequest.
fn parse_request(input: &[u8]) -> Option<(Vec<Asked<'_>>, Option<Vec<u8>>)> {
    let outer = der::read(input)?;
    if outer.tag != der::SEQUENCE {
        return None;
    }
    let parts = der::children(outer.content)?;
    let tbs = parts.first().filter(|p| p.tag == der::SEQUENCE)?;
    let fields = der::children(tbs.content)?;
    let mut asked = Vec::new();
    let mut nonce = None;
    let mut list_seen = false;
    for field in fields {
        if field.tag == der::SEQUENCE && !list_seen {
            list_seen = true;
            for request in der::children(field.content)? {
                let inner = der::children(request.content)?;
                let cert_id = *inner.first()?;
                let id = der::children(cert_id.content)?;
                if id.len() < 4 {
                    return None;
                }
                let alg = der::children(id[0].content)?;
                let oid = der::oid_string(alg.first()?.content)?;
                let digest = match oid.as_str() {
                    "1.3.14.3.2.26" => Some(MessageDigest::sha1()),
                    "2.16.840.1.101.3.4.2.1" => Some(MessageDigest::sha256()),
                    "2.16.840.1.101.3.4.2.2" => Some(MessageDigest::sha384()),
                    "2.16.840.1.101.3.4.2.3" => Some(MessageDigest::sha512()),
                    _ => None,
                };
                asked.push(Asked {
                    cert_id,
                    hash: digest,
                    name_hash: id[1].content,
                    key_hash: id[2].content,
                    serial: der::hex(id[3].content),
                });
            }
        } else if field.is_context(2) {
            let extensions = der::read(field.content)?;
            for one in der::children(extensions.content)? {
                let ext = der::children(one.content)?;
                if der::oid_string(ext.first()?.content)?.as_str() == NONCE_OID
                {
                    nonce = Some(ext.last()?.content.to_vec());
                }
            }
        }
    }
    list_seen.then_some((asked, nonce))
}

/// `nonceSize()`: an OCTET STRING inside the extension's value, or the
/// value itself.
fn nonce_size(value: &[u8]) -> usize {
    match der::read(value) {
        Some(e) if e.tag == der::OCTET_STRING && e.rest.is_empty() => {
            e.content.len()
        }
        _ => value.len(),
    }
}

impl Authority {
    /// `answerOcsp()`.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn answer_ocsp(
        &self,
        scope: &str,
        ca: &str,
        request: &[u8],
    ) -> OcspAnswer {
        self.answer_ocsp_at(scope, ca, request, Utc::now())
    }

    /// The same at a given moment (a vector's).
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn answer_ocsp_at(
        &self,
        scope: &str,
        ca: &str,
        request: &[u8],
        now: DateTime<Utc>,
    ) -> OcspAnswer {
        // THE ROOT IS FOUND FROM ANY SCOPE, its list read from the scope
        // asked (`authorityFor()` and `listFor()` as Node has them): only
        // `service/root` names the Root's own list — `default/root` signs
        // an empty one, which is Node's answer too.
        let id = scope_id(scope);
        let Some(tier) = self.tier_for(&id, ca) else {
            return refused(6, "unauthorized", codes::STS_PKI_0065);
        };
        let Some((asked, nonce)) = parse_request(request) else {
            return refused(1, "malformedRequest", codes::STS_PKI_0066);
        };
        if let Some(n) = &nonce {
            let size = nonce_size(n);
            if !(1..=32).contains(&size) {
                return refused(1, "malformedRequest", codes::STS_PKI_0132);
            }
        }
        let Ok(issuer) = Certificate::from_pem(
            tier.get("certificatePem")
                .and_then(Json::as_str)
                .unwrap_or(""),
        ) else {
            return refused(2, "internalError", codes::STS_PKI_0067);
        };
        let now = certificate_instant(Some(now.timestamp_millis()));
        let lifetime = self.config().crl_lifetime_ms();
        let next =
            DateTime::from_timestamp_millis(now.timestamp_millis() + lifetime)
                .unwrap_or(now);
        let key_bits = spki_bits(&issuer);
        let mut responses = Vec::new();
        let mut reported = Vec::new();
        for one in &asked {
            let mine = one.hash.is_some_and(|md| {
                hash(md, &issuer.subject_der)
                    .is_ok_and(|h| h.as_ref() == one.name_hash)
                    && hash(md, &key_bits)
                        .is_ok_and(|h| h.as_ref() == one.key_hash)
            });
            let status = if !mine {
                reported
                    .push(json!({ "serial": one.serial, "status": "unknown",
                    "why": "another issuer" }));
                vec![0x82, 0x00]
            } else if let Some(revoked) = self.is_revoked(&id, ca, &one.serial)
            {
                let at = revoked
                    .get("revokedAt")
                    .and_then(Json::as_str)
                    .and_then(ms_of)
                    .map(|ms| certificate_instant(Some(ms)))
                    .unwrap_or(now);
                let mut info = vec![generalized(&at)];
                let code = revoked
                    .get("reasonCode")
                    .and_then(Json::as_i64)
                    .unwrap_or(0);
                if code != 0 {
                    info.push(der::context(0, true, &enumerated(code)));
                }
                reported.push(json!({ "serial": one.serial, "status": "revoked",
                    "reason": revoked.get("reason").cloned().unwrap_or(Json::Null) }));
                der::context(1, true, &info.concat())
            } else if self.issued_here(&id, ca, &one.serial) {
                reported
                    .push(json!({ "serial": one.serial, "status": "good" }));
                vec![0x80, 0x00]
            } else {
                reported
                    .push(json!({ "serial": one.serial, "status": "unknown",
                    "why": "no record of that serial" }));
                vec![0x82, 0x00]
            };
            responses.push(der::sequence(&[
                one.cert_id.raw.to_vec(),
                status,
                generalized(&now),
                der::context(0, true, &generalized(&next)),
            ]));
        }
        if !asked.is_empty()
            && reported.iter().all(|r| {
                r.get("why").and_then(Json::as_str) == Some("another issuer")
            })
        {
            return refused(6, "unauthorized", codes::STS_PKI_0133);
        }
        let signed = (|| -> PkiResult<Vec<u8>> {
            let mut data = vec![
                der::context(2, true, &der::octet_string(&sha1(&key_bits))),
                generalized(&now),
                der::sequence(&responses),
            ];
            if let Some(n) = &nonce {
                data.push(der::context(
                    1,
                    true,
                    &der::sequence(&[extension(NONCE_OID, false, n)?]),
                ));
            }
            let data = der::sequence(&data);
            let sig = status_signature_alg(&tier)?;
            let alg = algorithms::certificate_signature_identifier(&sig)?;
            let key = SigningKey::from_pem(
                tier.get("privateKeyPem")
                    .and_then(Json::as_str)
                    .unwrap_or(""),
            )?;
            let signature = sign_bytes(&sig, &key, &data)?;
            let cert = pem_to_der(
                tier.get("certificatePem")
                    .and_then(Json::as_str)
                    .unwrap_or(""),
            )?;
            let basic = der::sequence(&[
                data,
                alg,
                der::bit_string(&signature),
                der::context(0, true, &der::sequence(&[cert])),
            ]);
            Ok(der::sequence(&[
                enumerated(0),
                der::context(
                    0,
                    true,
                    &der::sequence(&[
                        der::oid(BASIC_OID)?,
                        der::octet_string(&basic),
                    ]),
                ),
            ]))
        })();
        match signed {
            Ok(der) => OcspAnswer {
                der,
                status: "successful",
                code: None,
                answers: reported,
                this_update: time::iso(&now),
                next_update: time::iso(&next),
                nonce: nonce.is_some(),
            },
            Err(e) => {
                tracing::error!(
                    "{}pki_revocation: an OCSP response from the \"{}\" authority could not be \
                     signed: {}",
                    sts_core::log::tag(codes::STS_PKI_0067),
                    ca,
                    e
                );
                refused(2, "internalError", codes::STS_PKI_0067)
            }
        }
    }
}
