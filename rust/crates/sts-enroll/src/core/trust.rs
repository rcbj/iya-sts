// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A CERTIFICATE AS THE CREDENTIAL: `pki.verifyLeaf()` and
//! `authenticatePresentedCertificate()` / `authenticateCertificate()`.
//!
//! Three checks, real in both modes: the certificate verifies to THIS
//! REALM's Intermediate and the service Root with this service's own
//! register consulted (a certificate from another realm does not pass
//! through this Intermediate); it certifies `clientAuth` where it is used
//! as a TLS client credential; and its `urn:sts:` subjectAltName names an
//! entry that HOLDS this serial unrevoked.
//!
//! `verifyLeaf()` here is Node's for a path this service issued: the
//! presented path completed by following issuer to subject through the
//! realm's own tiers, every link's signature, names and validity, the
//! anchor, the Intermediate, RFC 5280's issuer rules (`sts-pki`'s
//! `path_rule_problem()`), and the register — each certificate looked up
//! at the authority that signed it. NOT here: the alternative-signature
//! (hybrid) checks and paranoid mode's field checks, neither of which a
//! classical enrolled certificate reaches.

use serde_json::Value as Json;
use sts_core::errors::codes;
use sts_core::realm;
use sts_pki::x509::keys::{der_to_pem, pem_to_der};
use sts_pki::x509::read::Certificate;

use super::{
    entry_from_uri, normal_serial, str_of, Core, Entry, Outcome, Principal,
    Refusal,
};

const CLIENT_AUTH_OID: &str = "1.3.6.1.5.5.7.3.2";

/// The `URI:` names of a certificate's subjectAltName.
#[tracing::instrument(level = "trace", skip_all)]
pub fn san_uris(cert: &Certificate) -> Vec<String> {
    let Some(ext) = cert.extension("2.5.29.17") else {
        return Vec::new();
    };
    let Some(seq) = sts_pki::der::read(&ext.value) else {
        return Vec::new();
    };
    sts_pki::der::children(seq.content)
        .unwrap_or_default()
        .iter()
        .filter(|n| n.tag == 0x86)
        .map(|n| n.content.iter().map(|&b| char::from(b)).collect())
        .collect()
}

/// The extended key usages a certificate certifies.
#[tracing::instrument(level = "trace", skip_all)]
pub fn extended_key_usages(cert: &Certificate) -> Vec<String> {
    let Some(ext) = cert.extension("2.5.29.37") else {
        return Vec::new();
    };
    let Some(seq) = sts_pki::der::read(&ext.value) else {
        return Vec::new();
    };
    sts_pki::der::children(seq.content)
        .unwrap_or_default()
        .iter()
        .filter_map(|o| sts_pki::der::oid_string(o.content))
        .collect()
}

/// `entryNamedByCertificate(certificate)`: the one person or application
/// a certificate's `urn:sts:` subjectAltName names, READ, NOT BELIEVED.
#[tracing::instrument(level = "debug", skip_all)]
pub fn entry_named_by_certificate(der: &[u8]) -> Option<Entry> {
    let cert = Certificate::from_der(der).ok()?;
    let named: Vec<Entry> = san_uris(&cert)
        .iter()
        .filter_map(|u| entry_from_uri(u))
        .collect();
    (named.len() == 1).then(|| named[0].clone())
}

fn strip(pem: &str) -> Vec<u8> {
    pem_to_der(pem).unwrap_or_default()
}

impl Core {
    /// `pki.verifyLeaf(realm, leafPem, chain)` for the ambient realm.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn verify_leaf(
        &self,
        leaf_pem: &str,
        presented: &[String],
    ) -> Outcome<()> {
        let id = realm::current_id();
        let authority = self.authority();
        let anchors = authority.trust_anchors_for(&id);
        if anchors.is_empty() {
            return Err(Refusal::new(
                codes::STS_PKI_0014,
                401,
                format!(
                    "The \"{}\" realm has no certificate authority, so there is no anchor to \
                     build a path to.",
                    id
                ),
            ));
        }
        let mut path: Vec<String> = vec![leaf_pem.to_string()];
        path.extend(presented.iter().cloned());
        let row = authority.raw_row_for(&id).unwrap_or(Json::Null);
        let read = |pem: &str| Certificate::from_pem(pem).ok();
        let terminates = path
            .last()
            .and_then(|p| read(p))
            .is_some_and(|c| c.subject() == c.issuer());
        // The tiers that may continue the path: every Issuing CA, the
        // Intermediate, the Root — each named with the CA id it is.
        let mut candidates: Vec<(String, String)> = Vec::new();
        if let Some(issuing) = row.get("issuing").and_then(Json::as_object) {
            for (ca, tier) in issuing {
                candidates.push((
                    ca.clone(),
                    str_of(tier, "certificatePem").to_string(),
                ));
            }
        }
        if let Some(i) = row.get("intermediate").filter(|i| !i.is_null()) {
            candidates.push((
                "intermediate".into(),
                str_of(i, "certificatePem").to_string(),
            ));
        }
        if let Some(root) = authority.service_root() {
            candidates.push((
                "root".into(),
                str_of(&root, "certificatePem").to_string(),
            ));
        }
        if !terminates {
            for _ in 0..8 {
                let Some(top) = path.last().and_then(|p| read(p)) else {
                    break;
                };
                if top.subject() == top.issuer() {
                    break;
                }
                let next = candidates.iter().find(|(_, pem)| {
                    read(pem).is_some_and(|c| c.subject() == top.issuer())
                        && !path.iter().any(|had| strip(had) == strip(pem))
                });
                let Some((_, pem)) = next else {
                    break;
                };
                path.push(pem.clone());
            }
        }
        let refs: Vec<&str> = path.iter().map(String::as_str).collect();
        let links = sts_pki::x509::read::verify_chain(&refs).map_err(|e| {
            Refusal::new(
                codes::STS_PKI_0015,
                401,
                format!("The certificate path could not be read: {}", e.0),
            )
        })?;
        for link in &links {
            let flag =
                |k: &str| link.get(k).and_then(Json::as_bool).unwrap_or(false);
            if !flag("signatureValid") {
                let error = str_of(link, "error");
                return Err(Refusal::new(
                    codes::STS_PKI_0016,
                    401,
                    format!(
                        "The certificate \"{}\" is not signed by \"{}\"{}.",
                        str_of(link, "subject"),
                        str_of(link, "signedBy"),
                        if error.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", error)
                        }
                    ),
                ));
            }
            if !flag("namesMatch") {
                return Err(Refusal::new(
                    codes::STS_PKI_0017,
                    401,
                    format!(
                        "The certificate \"{}\" names \"{}\" as its issuer and the next \
                         certificate in the path is \"{}\".",
                        str_of(link, "subject"),
                        str_of(link, "issuer"),
                        str_of(link, "signedBy")
                    ),
                ));
            }
            if flag("expired") {
                return Err(Refusal::new(
                    codes::STS_PKI_0018,
                    401,
                    format!(
                        "The certificate \"{}\" has expired.",
                        str_of(link, "subject")
                    ),
                ));
            }
            if flag("notYetValid") {
                return Err(Refusal::new(
                    codes::STS_PKI_0019,
                    401,
                    format!(
                        "The certificate \"{}\" is not valid yet.",
                        str_of(link, "subject")
                    ),
                ));
            }
        }
        let top = path.last().map(|p| strip(p)).unwrap_or_default();
        if !anchors.iter().any(|a| strip(a) == top) {
            return Err(Refusal::new(
                codes::STS_PKI_0020,
                401,
                "The path is internally consistent and does not end at this service's Root CA. \
                 A chain to somebody else's anchor verifies every link and proves nothing here.",
            ));
        }
        let ours = row
            .get("intermediate")
            .map(|i| strip(str_of(i, "certificatePem")))
            .unwrap_or_default();
        if ours.is_empty() || !path.iter().any(|p| strip(p) == ours) {
            return Err(Refusal::new(
                codes::STS_PKI_0021,
                401,
                format!(
                    "The path ends at this service's Root CA and does NOT pass through the \
                     \"{}\" realm's own Intermediate CA, so it was issued somewhere else in this \
                     service. One Root is shared by every realm — the Intermediate is what a \
                     realm has of its own, and it is the boundary.",
                    id
                ),
            ));
        }
        let entries: Vec<sts_pki::path::entry::Entry> = path
            .iter()
            .filter_map(|p| sts_pki::path::entry::Entry::from_der(&strip(p)))
            .collect();
        let refs: Vec<&sts_pki::path::entry::Entry> = entries.iter().collect();
        if let Some(problem) =
            sts_pki::path::rules::path_rule_problem(&refs, &Default::default())
        {
            let subject = links
                .get(problem.index)
                .map(|l| str_of(l, "subject").to_string())
                .unwrap_or_default();
            let why = match problem.check {
                "not-ca" => format!(
                    "The certificate \"{}\" signs the one below it and is not a certificate \
                     authority (it carries no basicConstraints cA=TRUE). A chain through an \
                     end-entity certificate verifies every signature and vouches for nothing.",
                    subject
                ),
                "key-cert-sign" => format!(
                    "The certificate \"{}\" carries a KeyUsage that does not permit \
                     keyCertSign, so it may not sign the certificate below it.",
                    subject
                ),
                _ => format!("The certificate path breaks RFC 5280: {}.", problem.why),
            };
            return Err(Refusal::new(
                problem.code.unwrap_or(codes::STS_PKI_0158),
                401,
                why,
            ));
        }
        // The register: each certificate at the authority that signed it.
        for (i, pem) in
            path.iter().enumerate().take(path.len().saturating_sub(1))
        {
            let issuer = strip(&path[i + 1]);
            let Some((ca, _)) =
                candidates.iter().find(|(_, p)| strip(p) == issuer)
            else {
                continue;
            };
            let Some(cert) = read(pem) else {
                continue;
            };
            let serial = sts_pki::der::hex(&cert.serial);
            let scope = if ca == "root" {
                sts_pki::authority::catalog::SERVICE_SCOPE.to_string()
            } else {
                id.clone()
            };
            if let Some(hit) = authority.is_revoked(&scope, ca, &serial) {
                return Err(Refusal::new(
                    codes::STS_PKI_0118,
                    401,
                    format!(
                        "The path anchors at this realm and was REFUSED ON REVOCATION \
                         (pki.revocationCheck is {}): the certificate serial {} was revoked \
                         ({}).",
                        self.setting_text("pki.revocationCheck"),
                        normal_serial(&serial),
                        str_of(&hit, "reason")
                    ),
                ));
            }
        }
        Ok(())
    }

    /// `authenticatePresentedCertificate(pem, via, { clientAuth })`.
    #[tracing::instrument(level = "debug", skip(self, pem))]
    pub fn authenticate_presented_certificate(
        &self,
        pem: &str,
        via: &str,
        client_auth: bool,
    ) -> Outcome<Principal> {
        if let Err(r) = self.verify_leaf(pem, &[]) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0018,
                401,
                format!(
                    "The client certificate does not verify to this realm's certificate \
                     authority: {}",
                    r.sentence
                ),
            ));
        }
        let cert = Certificate::from_pem(pem).ok();
        if client_auth
            && !cert.as_ref().is_some_and(|c| {
                extended_key_usages(c).iter().any(|e| e == CLIENT_AUTH_OID)
            })
        {
            return Err(Refusal::new(
                codes::STS_ENROLL_0019,
                401,
                "The client certificate does not certify TLS client authentication \
                 (clientAuth).",
            ));
        }
        let named: Vec<Entry> = cert
            .as_ref()
            .map(san_uris)
            .unwrap_or_default()
            .iter()
            .filter_map(|u| entry_from_uri(u))
            .collect();
        if named.len() != 1 {
            return Err(Refusal::new(
                codes::STS_ENROLL_0019,
                401,
                "The client certificate names no single person or application of this realm.",
            ));
        }
        let entry = named[0].clone();
        let serial = cert
            .as_ref()
            .map(|c| normal_serial(&sts_pki::der::hex(&c.serial)))
            .unwrap_or_default();
        let held = self
            .enrolled_of(&entry)
            .into_iter()
            .find(|one| normal_serial(str_of(one, "serialHex")) == serial);
        let Some(held) = held.filter(|h| {
            h.get("revoked")
                .is_none_or(|r| r.is_null() || r == &Json::Bool(false))
        }) else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0019,
                401,
                format!(
                    "The client certificate is not one the {} holds.",
                    entry.label()
                ),
            ));
        };
        Ok(Principal {
            kind: entry.kind.clone(),
            id: entry.id.clone(),
            admin: false,
            via: via.to_string(),
            realm: realm::current_id(),
            has_entry: true,
            certificate_serial: Some(serial),
            certificate_family: Some(str_of(&held, "family").to_string()),
            ..Default::default()
        })
    }

    /// `authenticateCertificate(req, via)`: the TLS client certificate on
    /// the connection, its leaf as DER.
    #[tracing::instrument(level = "debug", skip(self, leaf))]
    pub fn authenticate_certificate(
        &self,
        leaf: Option<&[u8]>,
        via: &str,
    ) -> Outcome<Principal> {
        let Some(der) = leaf.filter(|d| !d.is_empty()) else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0017,
                401,
                "No TLS client certificate was presented.",
            ));
        };
        self.authenticate_presented_certificate(
            &der_to_pem(der, "CERTIFICATE"),
            via,
            true,
        )
    }
}
