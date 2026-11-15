// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `common/pki_revocation.js`'s register: the RFC 5280 section 5.3.1
//! reasons, a revocation list PER CERTIFICATE AUTHORITY (a serial is only
//! unique within one issuer), kept in the same sealed `pki:<scope>` row as
//! the authority it is about (`revoked[<ca>]`, with `crlNumbers[<ca>]`
//! counting changes), `revoke()` and `release()` (only a `certificateHold`
//! may be undone), the addresses every certificate names
//! (`distributionPoints()`, `crlDn()`), and what an OCSP responder
//! answers `good` for (`issuedList()`, `issuedHere()`).

use chrono::Utc;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;

use super::catalog::{
    scope_id, scope_segment, use_case, PROCESS_SCOPE, SERVICE_SCOPE,
};
use super::hierarchy::{ms_of, Authority, Refusal};
use super::merge::normal_serial;
use crate::x509::time;

/// One of `REASONS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reason {
    pub id: &'static str,
    pub code: i64,
}

/// `REASONS`: RFC 5280's, without 7 (unused) and 8 (`removeFromCRL`, for
/// a delta CRL, which this service does not publish).
pub const REASONS: [Reason; 9] = [
    Reason {
        id: "unspecified",
        code: 0,
    },
    Reason {
        id: "keyCompromise",
        code: 1,
    },
    Reason {
        id: "cACompromise",
        code: 2,
    },
    Reason {
        id: "affiliationChanged",
        code: 3,
    },
    Reason {
        id: "superseded",
        code: 4,
    },
    Reason {
        id: "cessationOfOperation",
        code: 5,
    },
    Reason {
        id: "certificateHold",
        code: 6,
    },
    Reason {
        id: "privilegeWithdrawn",
        code: 9,
    },
    Reason {
        id: "aACompromise",
        code: 10,
    },
];

/// `reason()`.
#[tracing::instrument(level = "debug")]
pub fn reason(id: &str) -> Option<Reason> {
    REASONS.iter().copied().find(|r| r.id == id)
}

/// Where a certificate's issuer publishes (`distributionPoints()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Points {
    pub http: String,
    pub ldap: String,
    pub ocsp: String,
    pub ca_issuers: String,
    pub dn: String,
}

/// One authority with a list (`authorities()`).
#[derive(Debug, Clone)]
pub struct Listed {
    pub scope: String,
    pub ca: String,
    pub tier: Json,
    pub label: String,
}

/// What `revoke()` answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Revoked {
    pub entry: Json,
    pub already: bool,
}

/// JavaScript's `encodeURI()`.
fn encode_uri(text: &str) -> String {
    const KEEP: &str = "-_.!~*'();/?:@&=+$,#";
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || KEEP.contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// `a.localeCompare(b)` (`issuedList()` sorts by it): punctuation before
/// digits before letters, letters by case-folded value, then lower case
/// first — the collation `sts-registers`' `js::locale_compare()` holds, kept
/// here because this crate does not depend on that one.
fn locale_compare(a: &str, b: &str) -> std::cmp::Ordering {
    const PUNCTUATION: &str =
        "\t\n\u{b}\u{c}\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";
    let primary = |c: char| -> (u32, u32) {
        if let Some(at) = PUNCTUATION.find(c) {
            return (0, at as u32);
        }
        if c.is_ascii_digit() {
            return (1, c as u32);
        }
        if c.is_ascii_alphabetic() {
            return (2, c.to_ascii_lowercase() as u32);
        }
        (3, c.to_lowercase().next().unwrap_or(c) as u32)
    };
    let pa: Vec<(u32, u32)> = a.chars().map(primary).collect();
    let pb: Vec<(u32, u32)> = b.chars().map(primary).collect();
    pa.cmp(&pb).then_with(|| {
        let ta: Vec<bool> = a.chars().map(char::is_uppercase).collect();
        let tb: Vec<bool> = b.chars().map(char::is_uppercase).collect();
        ta.cmp(&tb)
    })
}

fn str_of<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

impl Authority {
    /// `crlDn()`: `cn=<ca>,[ou=service|ou=process,]ou=crl,<base>`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn crl_dn(&self, scope: &str, ca: &str) -> String {
        let base = self.config().distribution.directory_base_for(scope);
        let branch = match scope {
            SERVICE_SCOPE => "ou=service,",
            PROCESS_SCOPE => "ou=process,",
            _ => "",
        };
        format!("cn={},{}ou=crl,{}", ca, branch, base)
    }

    /// `distributionPoints()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn distribution_points(&self, scope: &str, ca: &str) -> Points {
        let config = self.config();
        let d = &config.distribution;
        let file = format!("{}/{}", scope_segment(scope), ca);
        let dn = self.crl_dn(scope, ca);
        let base = d.http_base();
        Points {
            http: format!("{}/pki/crl/{}.crl", base, file),
            ldap: format!(
                "ldap://{}:{}/{}?certificateRevocationList;binary",
                d.ldap_host(),
                d.ldap_port(),
                encode_uri(&dn)
            ),
            ocsp: format!("{}/pki/ocsp/{}", base, file),
            ca_issuers: format!("{}/pki/ca/{}.cer", base, file),
            dn,
        }
    }

    /// `authorities()`: the Root, then each built scope's Intermediate and
    /// Issuing CAs.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn authorities(&self, scopes: &[String]) -> Vec<Listed> {
        let mut out = Vec::new();
        if let Some(root) = self.service_root() {
            out.push(Listed {
                scope: SERVICE_SCOPE.to_string(),
                ca: "root".to_string(),
                tier: root,
                label: "Root CA".to_string(),
            });
        }
        for scope in scopes {
            let Some(row) = self.raw_row_for(scope) else {
                continue;
            };
            let Some(intermediate) =
                row.get("intermediate").filter(|i| !i.is_null())
            else {
                continue;
            };
            let label = if scope == PROCESS_SCOPE {
                "Process".to_string()
            } else {
                scope_id(scope)
            };
            out.push(Listed {
                scope: scope.clone(),
                ca: "intermediate".to_string(),
                tier: intermediate.clone(),
                label: format!("{} Intermediate CA", label),
            });
            if let Some(issuing) = row.get("issuing").and_then(Json::as_object)
            {
                for (id, tier) in issuing {
                    let named = use_case(id).map_or(id.as_str(), |u| u.label);
                    out.push(Listed {
                        scope: scope.clone(),
                        ca: id.clone(),
                        tier: tier.clone(),
                        label: format!("{} {} CA", label, named),
                    });
                }
            }
        }
        out
    }

    /// `listFor()`: an authority's revocation list.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list_for(&self, scope: &str, ca: &str) -> Vec<Json> {
        self.raw_row_for(scope)
            .and_then(|r| r.get("revoked")?.get(ca)?.as_array().cloned())
            .unwrap_or_default()
    }

    /// `isRevoked()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_revoked(
        &self,
        scope: &str,
        ca: &str,
        serial: &str,
    ) -> Option<Json> {
        let wanted = normal_serial(serial);
        self.list_for(scope, ca)
            .into_iter()
            .find(|one| normal_serial(str_of(one, "serialHex")) == wanted)
    }

    /// `revoke()`: a serial on its issuer's list, once — a second
    /// revocation leaves the first moment as it was.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revoke(
        &self,
        scope: &str,
        ca: &str,
        serial: &str,
        reason_id: Option<&str>,
        subject: &str,
        note: &str,
    ) -> Result<Revoked, Refusal> {
        let id = scope_id(scope);
        let no_authority = || {
            Refusal::new(
                codes::STS_PKI_0055,
                format!(
                    "There is no \"{}\" certificate authority in that scope, so nothing it \
                     issued can be revoked by it. A revocation is made BY AN ISSUER — a serial \
                     is only unique within one.",
                    ca
                ),
            )
        };
        if self.tier_for(&id, ca).is_none() {
            return Err(no_authority());
        }
        let serial_hex = normal_serial(serial);
        if serial_hex == "0" {
            return Err(Refusal::new(
                codes::STS_PKI_0056,
                "A revocation names a SERIAL NUMBER. It is the only thing a CRL entry and an \
                 OCSP answer have in common with the certificate they are about.",
            ));
        }
        let asked = reason_id.filter(|r| !r.is_empty()).unwrap_or("superseded");
        let Some(chosen) = reason(asked) else {
            return Err(Refusal::new(
                codes::STS_PKI_0057,
                format!(
                    "\"{}\" is not an RFC 5280 revocation reason. They are {}.",
                    asked,
                    REASONS.iter().map(|r| r.id).collect::<Vec<_>>().join(", ")
                ),
            ));
        };
        if let Some(already) = self.is_revoked(&id, ca, &serial_hex) {
            return Ok(Revoked {
                entry: already,
                already: true,
            });
        }
        let entry = json!({
            "serialHex": serial_hex,
            "revokedAt": time::iso(&Utc::now()),
            "reason": chosen.id,
            "reasonCode": chosen.code,
            "subject": subject,
            "note": note,
        });
        let Some(mut row) = self.raw_row_for(&id) else {
            return Err(Refusal::new(
                codes::STS_PKI_0055,
                "That scope holds no certificate authority.",
            ));
        };
        let mut list = self.list_for(&id, ca);
        list.push(entry.clone());
        if !row.get("revoked").is_some_and(Json::is_object) {
            row["revoked"] = json!({});
        }
        row["revoked"][ca] = Json::Array(list);
        if !row.get("crlNumbers").is_some_and(Json::is_object) {
            row["crlNumbers"] = json!({});
        }
        let n = row["crlNumbers"]
            .get(ca)
            .and_then(Json::as_i64)
            .unwrap_or(0);
        row["crlNumbers"][ca] = Json::from(n + 1);
        self.save_row(&id, &row);
        tracing::info!(
            "pki: certificate {} issued by the \"{}\" authority in \"{}\" was REVOKED ({}). It \
             is on that authority's CRL and its OCSP responder answers `revoked` for it from \
             now on. **NOTHING MAKES A RELYING PARTY CHECK** — what changed is that one which \
             does will see it.",
            serial_hex,
            ca,
            id,
            chosen.id
        );
        Ok(Revoked {
            entry,
            already: false,
        })
    }

    /// `release()`: a `certificateHold` taken off; every other reason is
    /// permanent.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn release(
        &self,
        scope: &str,
        ca: &str,
        serial: &str,
    ) -> Result<(), Refusal> {
        let id = scope_id(scope);
        let Some(held) = self.is_revoked(&id, ca, serial) else {
            return Err(Refusal::new(
                codes::STS_PKI_0058,
                format!(
                    "That serial is not on the {} authority's revocation list.",
                    ca
                ),
            ));
        };
        if str_of(&held, "reason") != "certificateHold" {
            return Err(Refusal::new(
                codes::STS_PKI_0059,
                format!(
                    "That certificate was revoked as \"{}\", which RFC 5280 makes PERMANENT. \
                     Only a `certificateHold` can be released: a validator is entitled to cache \
                     a permanent revocation for as long as the CRL it read says it is fresh, so \
                     undoing one here would produce a certificate this service calls good and \
                     half the world still calls revoked.",
                    str_of(&held, "reason")
                ),
            ));
        }
        let mut row = self.raw_row_for(&id).unwrap_or_else(|| json!({}));
        let wanted = normal_serial(serial);
        let kept: Vec<Json> = self
            .list_for(&id, ca)
            .into_iter()
            .filter(|one| normal_serial(str_of(one, "serialHex")) != wanted)
            .collect();
        row["revoked"][ca] = Json::Array(kept);
        if !row.get("crlNumbers").is_some_and(Json::is_object) {
            row["crlNumbers"] = json!({});
        }
        let n = row["crlNumbers"]
            .get(ca)
            .and_then(Json::as_i64)
            .unwrap_or(0);
        row["crlNumbers"][ca] = Json::from(n + 1);
        self.save_row(&id, &row);
        tracing::info!(
            "pki: the hold on certificate {} ({}, \"{}\") was RELEASED.",
            wanted,
            ca,
            id
        );
        Ok(())
    }

    /// `supersede()`: a replaced certificate on its issuer's list.
    #[tracing::instrument(level = "debug", skip(self, tier))]
    pub fn supersede(
        &self,
        scope: &str,
        ca: &str,
        tier: &Json,
        note: &str,
    ) -> bool {
        let serial = str_of(tier, "serialHex");
        if serial.is_empty() {
            return false;
        }
        match self.revoke(
            scope,
            ca,
            serial,
            Some("superseded"),
            str_of(tier, "subject"),
            note,
        ) {
            Ok(_) => true,
            Err(r) => {
                tracing::warn!(
                    "{}pki: {} was replaced and could not be put on a revocation list: {}",
                    sts_core::log::tag(codes::STS_PKI_0033),
                    str_of(tier, "subject"),
                    r.sentence()
                );
                false
            }
        }
    }

    /// `issuedList()`: every serial an authority issued that this service
    /// knows — the slot certificates, the Issuing CAs under an
    /// Intermediate, every scope's Intermediate under the Root, the stored
    /// objects and the issued register — once each, by subject.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn issued_list(&self, scope: &str, ca: &str) -> Vec<Json> {
        let now = Utc::now().timestamp_millis();
        let mut out: Vec<Json> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut add = |serial: &str,
                       subject: &str,
                       not_after: &str,
                       kind: &str,
                       label: String| {
            let key = normal_serial(serial);
            if key == "0" || !seen.insert(key.clone()) {
                return;
            }
            let expired = !not_after.is_empty()
                && ms_of(not_after).is_some_and(|t| t < now);
            out.push(json!({ "serialHex": key, "subject": subject,
                "notAfter": not_after, "kind": kind, "label": label,
                "expired": expired }));
        };
        for one in self.certificates_for(scope, ca) {
            let label = match (str_of(&one, "label"), str_of(&one, "slot")) {
                ("", slot) => slot.to_string(),
                (l, _) => l.to_string(),
            };
            add(
                str_of(&one, "serialHex"),
                str_of(&one, "subject"),
                str_of(&one, "notAfter"),
                "leaf",
                label,
            );
        }
        let row = self.raw_row_for(scope);
        if ca == "intermediate" {
            if let Some(issuing) = row
                .as_ref()
                .and_then(|r| r.get("issuing"))
                .and_then(Json::as_object)
            {
                for (id, tier) in issuing {
                    let named = use_case(id).map_or(id.as_str(), |u| u.label);
                    add(
                        str_of(tier, "serialHex"),
                        str_of(tier, "subject"),
                        str_of(tier, "notAfter"),
                        "issuing-ca",
                        format!("{} Issuing CA", named),
                    );
                }
            }
        }
        if ca == "root" {
            let mut scopes = self.known_scopes();
            scopes.push(PROCESS_SCOPE.to_string());
            for one in scopes {
                if let Some(int) = self
                    .raw_row_for(&one)
                    .and_then(|r| r.get("intermediate").cloned())
                    .filter(|i| !i.is_null())
                {
                    let named = if one == PROCESS_SCOPE {
                        "process".to_string()
                    } else {
                        scope_id(&one)
                    };
                    add(
                        str_of(&int, "serialHex"),
                        str_of(&int, "subject"),
                        str_of(&int, "notAfter"),
                        "intermediate-ca",
                        format!("{} Intermediate CA", named),
                    );
                }
            }
        }
        for one in self.objects(scope) {
            let label = match (str_of(&one, "label"), str_of(&one, "name")) {
                ("", name) => name.to_string(),
                (l, _) => l.to_string(),
            };
            add(
                str_of(&one, "serialHex"),
                str_of(&one, "subject"),
                str_of(&one, "notAfter"),
                "object",
                label,
            );
        }
        for one in self.issued_key_pairs_for(scope, ca) {
            let identifier = str_of(&one, "identifier");
            let label = if identifier.is_empty() {
                String::new()
            } else {
                format!(
                    "{} {} ({})",
                    match str_of(&one, "subjectKind") {
                        "" => "application",
                        k => k,
                    },
                    identifier,
                    match str_of(&one, "purpose") {
                        "" => "jwt",
                        p => p,
                    }
                )
            };
            add(
                str_of(&one, "serialHex"),
                str_of(&one, "subject"),
                str_of(&one, "notAfter"),
                "key-pair",
                label,
            );
        }
        out.sort_by(|a, b| {
            locale_compare(str_of(a, "subject"), str_of(b, "subject"))
        });
        out
    }

    /// `issuedHere()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn issued_here(&self, scope: &str, ca: &str, serial: &str) -> bool {
        let wanted = normal_serial(serial);
        self.issued_list(scope, ca)
            .iter()
            .any(|one| str_of(one, "serialHex") == wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uri_keeps_what_javascript_keeps() {
        assert_eq!(
            encode_uri("cn=root,ou=service,ou=crl,dc=example,dc=com"),
            "cn=root,ou=service,ou=crl,dc=example,dc=com"
        );
        assert_eq!(encode_uri("a b"), "a%20b");
    }
}
