// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `pki/pki_service.ts`'s public surface, as answers a router sends: a CRL
//! at `GET /pki/crl/{scope}/{ca}.crl`, an authority's certificate at
//! `GET /pki/ca/{scope}/{ca}.cer`, the OCSP responder at `GET|POST
//! /pki/ocsp/{scope}/{ca}` (RFC 6960 appendix A.1.1's two transports), and
//! the index at `GET /pki/revocation` — every status, header and sentence
//! Node's. No gate: revocation is published for anybody to read.
//!
//! `/pki/chain/{scope}/{sha256}.pem` (the chain a signed token's `x5u`
//! names) is `jose_certificate_header.js`'s, the JOSE family's, and is not
//! answered here yet.
//!
//! What is the runtime's: the plain-HTTP listener on `pki.httpPort`
//! (`listen()`), which answers these paths, SCEP and `/healthcheck` and
//! refuses everything else with [`revocation_only_refusal`].

use chrono::{DateTime, Utc};
use openssl::sha::{sha1, sha256};
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use super::catalog::{scope_from_segment, scope_segment};
use super::hierarchy::{ms_of, Authority};
use super::ocsp::OcspAnswer;
use crate::der;
use crate::x509::keys::pem_to_der;

/// One response.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    /// What the response is marked with (`errorCodes.mark(res, …)`).
    pub code: Option<ErrorCode>,
}

fn refuse(status: u16, code: ErrorCode, sentence: String) -> Answer {
    Answer {
        status,
        headers: vec![
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
            ("Cache-Control", "no-store".to_string()),
        ],
        body: format!("{}\n", sentence).into_bytes(),
        code: Some(code),
    }
}

/// `cacheSeconds()`.
fn cache_seconds(authority: &Authority) -> i64 {
    authority.config().crl_lifetime_ms() / 1000
}

/// RFC 7231's IMF-fixdate, `toUTCString()`.
fn http_date(t: &DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// `crlFor()`.
#[tracing::instrument(level = "debug", skip(authority))]
pub fn crl_for(authority: &Authority, segment: &str, ca_file: &str) -> Answer {
    let ca = ca_file.strip_suffix(".crl").unwrap_or(ca_file);
    let scope = scope_from_segment(segment);
    if authority.tier_for(&scope, ca).is_none() {
        return refuse(
            404,
            codes::STS_PKI_0068,
            format!(
                "There is no \"{}\" certificate authority in the \"{}\" scope of this service, \
                 so there is no revocation list for it. GET /pki/revocation lists every CRL \
                 this service publishes.",
                ca, segment
            ),
        );
    }
    match authority.build_crl(&scope, ca) {
        Ok(made) => Answer {
            status: 200,
            headers: vec![
                ("Content-Type", "application/pkix-crl".to_string()),
                ("Content-Length", made.der.len().to_string()),
                (
                    "Cache-Control",
                    format!("public, max-age={}", cache_seconds(authority)),
                ),
            ],
            body: made.der,
            code: None,
        },
        Err(r) => refuse(500, r.code, r.sentence()),
    }
}

/// `caCertificateFor()`.
#[tracing::instrument(level = "debug", skip(authority))]
pub fn ca_certificate_for(
    authority: &Authority,
    segment: &str,
    ca_file: &str,
) -> Answer {
    let ca = ca_file.strip_suffix(".cer").unwrap_or(ca_file);
    let scope = scope_from_segment(segment);
    let Some(tier) = authority.tier_for(&scope, ca) else {
        return refuse(
            404,
            codes::STS_PKI_0070,
            format!(
                "There is no \"{}\" certificate authority in the \"{}\" scope of this service.",
                ca, segment
            ),
        );
    };
    let der = pem_to_der(
        tier.get("certificatePem")
            .and_then(Json::as_str)
            .unwrap_or(""),
    )
    .unwrap_or_default();
    Answer {
        status: 200,
        headers: vec![
            ("Content-Type", "application/pkix-cert".to_string()),
            ("Content-Length", der.len().to_string()),
            ("Cache-Control", "no-cache".to_string()),
            ("ETag", format!("\"{}\"", der::hex(&sha256(&der)))),
        ],
        body: der,
        code: None,
    }
}

/// `sendOcsp()`.
fn send_ocsp(made: OcspAnswer) -> Answer {
    if made.status != "successful" || made.next_update.is_empty() {
        return Answer {
            status: 200,
            headers: vec![
                ("Content-Type", "application/ocsp-response".to_string()),
                ("Content-Length", made.der.len().to_string()),
                ("Cache-Control", "no-store".to_string()),
            ],
            body: made.der,
            code: made.code,
        };
    }
    let next = ms_of(&made.next_update).unwrap_or(0);
    let this = ms_of(&made.this_update).unwrap_or(0);
    let max_age = ((next - Utc::now().timestamp_millis()) / 1000).max(0);
    let at = |ms| {
        DateTime::from_timestamp_millis(ms)
            .map(|t| http_date(&t))
            .unwrap_or_default()
    };
    Answer {
        status: 200,
        headers: vec![
            ("Content-Type", "application/ocsp-response".to_string()),
            ("Content-Length", made.der.len().to_string()),
            (
                "Cache-Control",
                if made.nonce {
                    "private, max-age=0, no-transform".to_string()
                } else {
                    format!(
                        "max-age={}, public, no-transform, must-revalidate",
                        max_age
                    )
                },
            ),
            ("Last-Modified", at(this)),
            ("Expires", at(next)),
            ("ETag", format!("\"{}\"", der::hex(&sha1(&made.der)))),
        ],
        body: made.der,
        code: made.code,
    }
}

/// `POST /pki/ocsp/{scope}/{ca}`: the DER request as the body, at most
/// 64KB.
#[tracing::instrument(level = "debug", skip(authority, body))]
pub fn ocsp_post(
    authority: &Authority,
    segment: &str,
    ca: &str,
    body: &[u8],
) -> Answer {
    if body.len() > 65536 {
        return refuse(
            413,
            codes::STS_PKI_0073,
            "That OCSP request is larger than this responder accepts (64KB). A request for \
             one certificate is about eighty bytes."
                .to_string(),
        );
    }
    send_ocsp(authority.answer_ocsp(&scope_from_segment(segment), ca, body))
}

/// `GET /pki/ocsp/{scope}/{ca}/{base64}`: the request URL-encoded (a
/// space read back as `+`); anything not base64 is an empty request.
#[tracing::instrument(level = "debug", skip(authority))]
pub fn ocsp_get(
    authority: &Authority,
    segment: &str,
    ca: &str,
    encoded: &str,
) -> Answer {
    use base64::Engine;
    let text = encoded.replace(' ', "+");
    let valid = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c));
    let der = if valid {
        // node's Buffer.from(…, 'base64') reads both alphabets and stops at
        // the first character it does not know.
        let standard: String = text
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                o => o,
            })
            .filter(|c| *c != '=')
            .collect();
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(standard.as_bytes())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    send_ocsp(authority.answer_ocsp(&scope_from_segment(segment), ca, &der))
}

/// `GET /pki/ocsp/{scope}/{ca}` with nothing appended.
#[tracing::instrument(level = "debug", skip(authority))]
pub fn ocsp_bare_get(authority: &Authority, segment: &str, ca: &str) -> Answer {
    if authority
        .tier_for(&scope_from_segment(segment), ca)
        .is_none()
    {
        return refuse(
            404,
            codes::STS_PKI_0131,
            format!(
                "There is no \"{}\" certificate authority in the \"{}\" scope of this service, \
                 so there is no OCSP responder for it. GET /pki/revocation lists every \
                 responder this service answers.",
                ca, segment
            ),
        );
    }
    refuse(
        400,
        codes::STS_PKI_0130,
        format!(
            "This is the OCSP responder of the \"{}\" certificate authority in the \"{}\" \
             scope, and this request asked it nothing. RFC 6960 appendix A.1.1 defines two \
             transports on this address: POST the DER OCSPRequest here as \
             application/ocsp-request, or GET this address with \"/\" and the URL-encoded \
             base64 of the DER request appended. For example: openssl ocsp -issuer issuer.pem \
             -cert cert.pem -url <this URL> -CAfile root.pem",
            ca, segment
        ),
    )
}

/// `GET /pki/revocation`.
#[tracing::instrument(level = "debug", skip(authority))]
pub fn revocation_index(
    authority: &Authority,
    publish_to_directory: bool,
) -> Answer {
    let config = authority.config();
    let all = authority.authorities(&authority.known_scopes());
    let out = json!({
        "what": "Every certificate revocation list and OCSP responder this service \
                 publishes. There is one of each PER CERTIFICATE AUTHORITY, because a CRL is \
                 signed by an issuer and lists serials that issuer minted — a list per realm \
                 would be a document with no valid issuer.",
        "revocationIsPublishedNotEnforced": "This service publishes revocation and cannot \
                 make anybody consult it. A certificate revoked here goes on the list and its \
                 OCSP responder answers `revoked`; whether that stops anything depends \
                 entirely on the relying party, which is true of every certificate authority \
                 and is the reason a client author would point their stack here.",
        "crlLifetimeMinutes": config.crl_lifetime_minutes,
        "publishedToDirectory": publish_to_directory,
        "authorities": all.iter().map(|one| {
            let points = authority.distribution_points(&one.scope, &one.ca);
            json!({
                "scope": scope_segment(&one.scope),
                "ca": one.ca,
                "label": one.label,
                "subject": one.tier.get("subject").cloned().unwrap_or(Json::Null),
                "revokedCount": authority.list_for(&one.scope, &one.ca).len(),
                "crl": { "http": points.http, "ldap": points.ldap },
                "ocsp": points.ocsp,
                "caIssuers": points.ca_issuers,
                "directoryDn": points.dn,
            })
        }).collect::<Vec<_>>(),
    });
    let body = serde_json::to_string_pretty(&out).unwrap_or_default();
    Answer {
        status: 200,
        headers: vec![
            (
                "Content-Type",
                "application/json; charset=utf-8".to_string(),
            ),
            ("Cache-Control", "no-store".to_string()),
        ],
        body: body.into_bytes(),
        code: None,
    }
}

/// `revocationOnly()`: whether the plain-HTTP listener serves a path —
/// `/pki/…`, `/healthcheck` and SCEP, and nothing with `..` in it.
#[tracing::instrument(level = "debug")]
pub fn revocation_listener_serves(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or("");
    if path.contains("..") {
        return path == "/healthcheck";
    }
    if path.starts_with("/pki/") || path == "/healthcheck" {
        return true;
    }
    // SCEP_PATH: up to two segments (a realm prefix) before /enroll/scep.
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    for skip in 0..=2usize {
        if segments.len() >= skip + 2
            && segments[skip] == "enroll"
            && segments[skip + 1] == "scep"
            && segments[..skip].iter().all(|s| !s.is_empty())
        {
            return true;
        }
    }
    false
}

/// The 404 the plain-HTTP listener answers for anything else
/// (`STS-PKI-0134`).
#[tracing::instrument(level = "debug")]
pub fn revocation_only_refusal() -> Answer {
    Answer {
        status: 404,
        headers: vec![
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
            ("Cache-Control", "no-store".to_string()),
            ("X-Content-Type-Options", "nosniff".to_string()),
            ("X-Frame-Options", "DENY".to_string()),
            (
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
                    .to_string(),
            ),
        ],
        body: b"This plain-HTTP listener serves the revocation endpoints under /pki/, SCEP \
                under /enroll/scep, and /healthcheck, and nothing else. Everything else this \
                service answers is on its main port.\n"
            .to_vec(),
        code: Some(codes::STS_PKI_0134),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plain_listener_serves_what_node_serves() {
        assert!(revocation_listener_serves("/pki/crl/service/root.crl"));
        assert!(revocation_listener_serves("/healthcheck"));
        assert!(revocation_listener_serves("/enroll/scep"));
        assert!(revocation_listener_serves("/realm/acme/enroll/scep/x"));
        assert!(!revocation_listener_serves("/oauth2/token"));
        assert!(!revocation_listener_serves("/pki/../admin"));
    }
}
