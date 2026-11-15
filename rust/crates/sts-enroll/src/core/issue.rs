// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT GOES IN THE CERTIFICATE, ISSUING IT, AND THE RECORDS ON AN ENTRY:
//! `targetFromRequest()`, `namesFor()`, `subjectFor()`,
//! `applicationRules()`, `issue()`, `issueWithServerKey()`,
//! `enrolledOf()`, `findEnrolled()`, `revokeEnrolled()`, `serverKeyOf()`
//! and the realm listings.
//!
//! **THE RECORD IS NODE'S JSON, MEMBER FOR MEMBER, IN NODE'S ORDER**
//! (`stsEnrolledCertificate` / `appEnrolledCertificate`): Node reads what
//! Rust wrote and Rust what Node wrote (D11). A private key goes FIRST, as
//! `serial:<sealed PEM>` on `…EnrolledPrivateKey`, and only for a key this
//! service generated.

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::realm;
use sts_pki::authority::hierarchy::EnrolledSpec;

use super::csr::Requested;
use super::{
    family_label, is_ip, iso, ms_of, normal_host_name, normal_serial, now_ms,
    parse_json_values, str_of, stringify, Core, Entry, Outcome, Principal,
    Refusal, Resolved, DEVICE_PROFILE, FAMILIES,
};

/// What `issue()` is asked.
#[derive(Debug, Clone, Default)]
pub struct IssueSpec {
    pub family: String,
    pub profile: String,
    pub profile_defaulted: bool,
    pub principal: Option<Principal>,
    pub target: Option<Entry>,
    pub public_key_pem: String,
    pub requested: Requested,
    /// `client` or `server`.
    pub key_source: String,
    pub private_key_pem: String,
    pub key_alg: String,
    pub via: String,
    pub replaces: String,
}

/// `issue()`'s answer: the PUBLIC record, the entry, and whether it was
/// issued by an administrator for somebody else.
#[derive(Debug, Clone)]
pub struct Issued {
    pub record: Json,
    pub target: Entry,
    pub admin: bool,
    pub private_key_pem: String,
}

/// `targetFromRequest()`'s answer.
#[derive(Debug, Clone)]
pub struct Target {
    pub target: Entry,
    pub by: &'static str,
}

/// `publicRecord(one)`: no private key, and its state.
#[tracing::instrument(level = "trace", skip_all)]
pub fn public_record(one: &Json) -> Json {
    let mut out = one.clone();
    if let Some(o) = out.as_object_mut() {
        o.remove("privateKeyPem");
        let expired = ms_of(str_of(one, "notAfter")) < now_ms();
        let revoked = one
            .get("revoked")
            .is_some_and(|r| !r.is_null() && r != &json!(false));
        o.insert("expired".into(), Json::Bool(expired));
        o.insert(
            "status".into(),
            Json::from(if revoked {
                "revoked"
            } else if expired {
                "expired"
            } else {
                "valid"
            }),
        );
    }
    out
}

/// `mayBeOfFamily()`: false only when the text proves the record is not
/// the family's — no `\u` escape and no literal `"family": "<f>"`.
// A hot path: one test per stored value; no span.
pub fn may_be_of_family(value: &str, family: &str) -> bool {
    if !family
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || value.contains("\\u")
    {
        return true;
    }
    regex::Regex::new(&format!("\"family\"\\s*:\\s*\"{}\"", family))
        .map(|re| re.is_match(value))
        .unwrap_or(true)
}

/// `enrolledFrom(values, family)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn enrolled_from(values: &[String], family: Option<&str>) -> Vec<Json> {
    let wanted: Vec<String> = match family {
        Some(f) => values
            .iter()
            .filter(|v| may_be_of_family(v, f))
            .cloned()
            .collect(),
        None => values.to_vec(),
    };
    parse_json_values(&wanted)
        .into_iter()
        .filter(|one| family.is_none_or(|f| str_of(one, "family") == f))
        .map(|one| public_record(&one))
        .collect()
}

/// `subjectFor(entry, names)`: a certificate naming a host has the host as
/// its CN and the entry as its UID (#207).
#[tracing::instrument(level = "trace", skip_all)]
pub fn subject_for(entry: &Entry, names: &[(String, String)]) -> Vec<Json> {
    let host = names
        .iter()
        .find(|(k, _)| k == "dns")
        .or_else(|| names.iter().find(|(k, _)| k == "ip"));
    match host {
        None => vec![json!({ "name": "CN", "value": entry.id })],
        Some((_, h)) => vec![
            json!({ "name": "CN", "value": h }),
            json!({ "name": "UID", "value": entry.id }),
        ],
    }
}

fn clipped(text: &str, n: usize) -> String {
    // `String(x).slice(0, n)`: UTF-16 units.
    let units: Vec<u16> = text.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

/// RFC 4514 escaping of one value (`helpers.escapeRdnValue()`).
fn escape_rdn_value(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if "\\,+\"<>;=".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    if out.starts_with('#') {
        out.insert(0, '\\');
    }
    if out.starts_with(' ') {
        out.insert(0, '\\');
    }
    if out.ends_with(' ') && out.len() > 1 {
        out.pop();
        out.push_str("\\ ");
    }
    out
}

/// `helpers.dnRfc4514(cert.subject)`: node's lines, each value escaped,
/// leaf first; a one-line subject as it stands.
#[tracing::instrument(level = "trace", skip_all)]
pub fn dn_rfc4514(name_der: &[u8]) -> String {
    let lines = sts_pki::path::entry::name_lines(name_der);
    if lines.len() <= 1 {
        return lines.join("").trim().to_string();
    }
    let mut parts: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let t = line.trim();
            let (k, v) = t.split_once('=')?;
            Some(format!("{}={}", k, escape_rdn_value(v)))
        })
        .collect();
    parts.reverse();
    parts.join(",")
}

impl Core {
    /// `targetFromRequest(requested, commonName, principal)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn target_from_request(
        &self,
        requested: &Requested,
        common_name: &str,
        principal: Option<&Principal>,
    ) -> Outcome<Target> {
        let mut named: Vec<Entry> = Vec::new();
        for uri in &requested.uris {
            if let Some(e) = super::entry_from_uri(uri) {
                if !named.contains(&e) {
                    named.push(e);
                }
            }
        }
        if named.len() > 1 {
            return Err(Refusal::new(
                codes::STS_ENROLL_0022,
                400,
                format!(
                    "The request names {} different entries. One certificate maps to one \
                     person or application.",
                    named.len()
                ),
            ));
        }
        if let Some(one) = named.into_iter().next() {
            return Ok(Target {
                target: one,
                by: "urn",
            });
        }
        if let Some(p) = principal {
            if p.admin
                && !common_name.is_empty()
                && !(p.kind == "person" && common_name == p.id)
            {
                if let Ok(person) = self.resolve_entry("person", common_name) {
                    return Ok(Target {
                        target: person.entry,
                        by: "common-name",
                    });
                }
                if let Ok(app) = self.resolve_entry("application", common_name)
                {
                    return Ok(Target {
                        target: app.entry,
                        by: "common-name",
                    });
                }
            }
            if !p.has_entry {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0023,
                    400,
                    "An administrator with no entry of their own in this realm must name the \
                     entry the certificate is for, in a urn:sts:person: or \
                     urn:sts:application: subjectAltName or as the common name.",
                ));
            }
            return Ok(Target {
                target: p.entry(),
                by: "principal",
            });
        }
        Err(Refusal::new(
            codes::STS_ENROLL_0020,
            403,
            "Nobody authenticated, or nobody was named.",
        ))
    }

    /// `namesFor(resolved, profileId, requested)`: the names, built from
    /// the entry; every name requested must be the entry's. `(kind,
    /// value)`, the entry's URN first.
    #[tracing::instrument(level = "debug", skip(self, resolved))]
    pub fn names_for(
        &self,
        resolved: &Resolved,
        profile: &str,
        want: &Requested,
    ) -> Outcome<Vec<(String, String)>> {
        let entry = &resolved.entry;
        let uri = entry.uri();
        let mut names = vec![("uri".to_string(), uri.clone())];
        let add =
            |names: &mut Vec<(String, String)>, kind: &str, value: &str| {
                if !names.iter().any(|(k, v)| k == kind && v == value) {
                    names.push((kind.to_string(), value.to_string()));
                }
            };
        for one in &want.uris {
            if *one != uri {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0050,
                    403,
                    format!(
                        "The request asks for the name \"{}\", which the {} does not own. Only \
                         its own urn:sts: name may be requested.",
                        clipped(one, 200),
                        entry.label()
                    ),
                ));
            }
        }
        let mut hosts = 0;
        for one in &want.dns {
            let host = normal_host_name(one);
            if host.is_empty()
                || is_ip(&host)
                || !resolved.host_names.contains(&host)
            {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0051,
                    403,
                    format!(
                        "The host name \"{}\" is not registered on the {}. A host name is \
                         issued only when an administrator has registered it on the entry; \
                         this service never proves control of a name by dialling it.",
                        clipped(one, 253),
                        entry.label()
                    ),
                ));
            }
            add(&mut names, "dns", &host);
            hosts += 1;
        }
        for one in &want.ips {
            let address = normal_host_name(one);
            if !is_ip(&address) || !resolved.host_names.contains(&address) {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0051,
                    403,
                    format!(
                        "The address \"{}\" is not registered on the {}.",
                        clipped(one, 64),
                        entry.label()
                    ),
                ));
            }
            add(&mut names, "ip", &address);
            hosts += 1;
        }
        for one in &want.emails {
            if resolved.mail.is_empty()
                || one.to_lowercase() != resolved.mail.to_lowercase()
            {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0052,
                    403,
                    format!(
                        "The email address \"{}\" is not the mail attribute of the {}.",
                        clipped(one, 254),
                        entry.label()
                    ),
                ));
            }
            add(&mut names, "email", &resolved.mail);
        }
        for one in &want.upns {
            let owned: Vec<String> = [&resolved.upn, &resolved.mail]
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_lowercase())
                .collect();
            if !owned.contains(&one.to_lowercase()) {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0053,
                    403,
                    format!(
                        "The user principal name \"{}\" is neither the userPrincipalName nor \
                         the mail of the {}.",
                        clipped(one, 254),
                        entry.label()
                    ),
                ));
            }
            add(&mut names, "upn", one);
        }
        if (profile == "tls-server" || profile == "tls-server-client")
            && hosts == 0
        {
            let held = if resolved.host_names.is_empty() {
                format!("The {} has none registered.", entry.label())
            } else {
                format!(
                    "The {} has {} registered.",
                    entry.label(),
                    resolved.host_names.len()
                )
            };
            return Err(Refusal::new(
                codes::STS_ENROLL_0054,
                400,
                format!(
                    "A {} certificate names at least one host, and the request names none. {}",
                    profile, held
                ),
            ));
        }
        if profile == "email" && want.emails.is_empty() {
            if resolved.mail.is_empty() {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0055,
                    400,
                    format!(
                        "An S/MIME certificate carries the holder's email address, and the {} \
                         has no mail attribute.",
                        entry.label()
                    ),
                ));
            }
            add(&mut names, "email", &resolved.mail);
        }
        if profile == "smartcard-logon" && want.upns.is_empty() {
            let upn = if resolved.upn.is_empty() {
                &resolved.mail
            } else {
                &resolved.upn
            };
            if upn.is_empty() {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0056,
                    400,
                    format!(
                        "A smartcard logon certificate carries a user principal name, and the \
                         {} has neither userPrincipalName nor mail.",
                        entry.label()
                    ),
                ));
            }
            let upn = upn.clone();
            add(&mut names, "upn", &upn);
        }
        Ok(names)
    }

    /// `applicationRules(family, entry, asked, profileId)`: the profile,
    /// days and cap to issue with.
    fn application_rules(
        &self,
        family: &str,
        entry: &Entry,
        asked: &IssueSpec,
        profile: &str,
    ) -> Outcome<(String, i64, i64)> {
        let realm_days =
            self.setting_int(&format!("{}.certificateLifetimeDays", family));
        let realm_cap =
            self.setting_int("pki.enrollmentMaxCertificatesPerEntry");
        if entry.kind != "application" {
            return Ok((profile.to_string(), realm_days, realm_cap));
        }
        let id = &entry.id;
        if !self.d.gate.certificate_allowed(id, family) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0094,
                403,
                format!(
                    "The application \"{}\" is not declared for {}, so no certificate is \
                     issued to it over that protocol here.",
                    id,
                    family_label(family)
                ),
            ));
        }
        let view = self.d.applications.get(id).unwrap_or_default();
        let list_of = |name: &str| -> Vec<String> {
            view.field(name)
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let allowed = self.allowed_profiles(family, Some(entry));
        let mut chosen = profile.to_string();
        let own_default = list_of(&format!("{}DefaultProfile", family))
            .into_iter()
            .next()
            .unwrap_or_default();
        if asked.profile_defaulted
            && !own_default.is_empty()
            && allowed.contains(&own_default)
        {
            chosen = own_default;
        }
        let own = list_of(&format!("{}AllowedProfiles", family));
        if !own.is_empty() && !own.contains(&chosen) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0095,
                403,
                format!(
                    "The \"{}\" profile is not one the application \"{}\" may be issued over {} \
                     ({}AllowedProfiles: {}).",
                    chosen,
                    id,
                    family_label(family),
                    family,
                    own.join(", ")
                ),
            ));
        }
        let principal = asked.principal.clone().unwrap_or_default();
        let is_self = principal.kind == "application" && principal.id == *id;
        if family == "est" && is_self {
            let by_certificate = principal.certificate_serial.is_some();
            let refused_by = if by_certificate {
                (!self.est_switch("certificateAuthentication", Some(entry)))
                    .then_some(
                    "certificate authentication (estCertificateAuthentication)",
                )
            } else {
                (!self.est_switch("basicAuthentication", Some(entry)))
                    .then_some(
                        "its client id and secret (estBasicAuthentication)",
                    )
            };
            if let Some(what) = refused_by {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0096,
                    403,
                    format!(
                        "EST does not accept {} for the application \"{}\".",
                        what, id
                    ),
                ));
            }
        }
        if family == "est"
            && asked.key_source == "server"
            && !self.est_switch("serverKeyGeneration", Some(entry))
        {
            return Err(Refusal::new(
                codes::STS_ENROLL_0096,
                403,
                format!(
                    "EST /serverkeygen is not offered to the application \"{}\" \
                     (estServerKeyGeneration).",
                    id
                ),
            ));
        }
        let own_or = |realm_value: i64, attribute: &str| -> i64 {
            let mine = list_of(attribute)
                .into_iter()
                .next()
                .and_then(|t| t.parse::<f64>().ok())
                .unwrap_or(0.0);
            if mine.is_finite() && mine > 0.0 {
                mine as i64
            } else {
                realm_value
            }
        };
        Ok((
            chosen,
            own_or(realm_days, &format!("{}CertificateLifetimeDays", family)),
            own_or(realm_cap, "enrollMaxCertificates"),
        ))
    }

    fn audit_refusal(
        &self,
        family: &str,
        asked: &IssueSpec,
        refusal: Refusal,
    ) -> Refusal {
        self.d.audit.record(&json!({
            "category": "protocol", "action": "enrollment.issue.refused",
            "protocol": family_label(family), "outcome": "failure",
            "errorCode": refusal.code.as_str(),
            "actor": asked.principal.as_ref().map(|p| p.id.clone()).unwrap_or_default(),
            "target": asked.target.as_ref().map(Entry::uri).unwrap_or_default(),
            "summary": format!("a certificate was not issued over {}: {}",
                family_label(family), clipped(&refusal.sentence, 300)),
            "detail": { "profile": asked.profile,
                        "via": if asked.via.is_empty() { family } else { &asked.via } },
        }));
        refusal
    }

    /// `issue(spec)`.
    #[tracing::instrument(level = "debug", skip(self, asked))]
    pub async fn issue(&self, asked: &IssueSpec) -> Outcome<Issued> {
        let family = asked.family.as_str();
        if !FAMILIES.contains(&family) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0004,
                500,
                format!("Not an enrollment family: {}", family),
            ));
        }
        if let Some(retiring) = self.retiring_refusal() {
            tracing::info!(
                "{}enrollment: a {} certificate was refused. {}",
                sts_core::log::tag(retiring.code.as_str()),
                family_label(family),
                retiring.sentence
            );
            return Err(retiring);
        }
        if asked.profile == DEVICE_PROFILE {
            // `issueForDevice()` is not ported: there is no device register
            // in this runtime to keep the certificate on.
            return Err(Refusal::new(
                codes::STS_ENROLL_0011,
                503,
                "No directory is loaded in this process, so there is no entry a certificate \
                 could be issued for or kept on.",
            ));
        }
        let asked_profile = if asked.profile_defaulted {
            self.default_profile(family, asked.target.as_ref())
        } else {
            asked.profile.clone()
        };
        let profile = self
            .check_profile(family, &asked_profile, asked.target.as_ref(), false)
            .map_err(|r| self.audit_refusal(family, asked, r))?;
        let target = asked.target.clone().unwrap_or_default();
        let resolved = self
            .resolve_entry(&target.kind, &target.id)
            .map_err(|r| self.audit_refusal(family, asked, r))?;
        let admin = self
            .authorize_target(asked.principal.as_ref(), &resolved.entry)
            .map_err(|r| self.audit_refusal(family, asked, r))?;
        let (profile, days, cap) = self
            .application_rules(family, &resolved.entry, asked, &profile)
            .map_err(|r| self.audit_refusal(family, asked, r))?;
        if family == "est"
            && asked.key_source == "server"
            && resolved.entry.kind != "application"
            && !self.est_switch("serverKeyGeneration", None)
        {
            return Err(self.audit_refusal(
                family,
                asked,
                Refusal::new(
                    codes::STS_EST_0005,
                    501,
                    "Server-side key generation is turned off for EST in this realm \
                     (est.serverKeyGeneration).",
                ),
            ));
        }
        let names = self
            .names_for(&resolved, &profile, &asked.requested)
            .map_err(|r| self.audit_refusal(family, asked, r))?;
        let now = now_ms();
        let existing = parse_json_values(&resolved.held("certificate"));
        let replacing = if asked.replaces.is_empty() {
            String::new()
        } else {
            normal_serial(&asked.replaces)
        };
        let counted = existing
            .iter()
            .filter(|one| ms_of(str_of(one, "notAfter")) > now)
            .filter(|one| normal_serial(str_of(one, "serialHex")) != replacing)
            .count() as i64;
        if !replacing.is_empty() {
            let old = self.find_enrolled(&replacing, None);
            if old.as_ref().is_none_or(|o| o.entry != resolved.entry) {
                return Err(self.audit_refusal(
                    family,
                    asked,
                    Refusal::new(
                        codes::STS_ENROLL_0092,
                        409,
                        format!(
                            "The certificate this request renews (serial {}) is not recorded \
                             as issued to the {} in this realm, so it could not be superseded; \
                             no certificate was issued.",
                            replacing,
                            resolved.entry.label()
                        ),
                    ),
                ));
            }
        }
        if counted >= cap {
            return Err(self.audit_refusal(
                family,
                asked,
                Refusal::new(
                    codes::STS_ENROLL_0040,
                    409,
                    format!(
                        "The {} already holds {} unexpired enrolled certificate(s), the most \
                         pki.enrollmentMaxCertificatesPerEntry allows. Revoke one first.",
                        resolved.entry.label(),
                        counted
                    ),
                ),
            ));
        }
        let (organisation, country) = self.organisation_of();
        let mut subject = subject_for(&resolved.entry, &names);
        subject.push(json!({ "name": "O", "value": organisation }));
        if !country.is_empty() {
            subject.push(json!({ "name": "C", "value": country }));
        }
        let san: Vec<Json> = names
            .iter()
            .map(|(k, v)| json!({ "kind": k, "value": v }))
            .collect();
        let holder = if resolved.entry.kind == "person" {
            self.d.entries.subject_for_name(&resolved.entry.id)
        } else {
            String::new()
        };
        let spec = EnrolledSpec {
            subject: Json::Array(subject),
            public_key_pem: asked.public_key_pem.clone(),
            profile: profile.clone(),
            days,
            subject_alt_name: san,
            identifier: resolved.entry.id.clone(),
            subject_kind: resolved.entry.kind.clone(),
            holder_subject: holder,
        };
        let authority = self.d.authority.clone();
        let scope = realm::current_id();
        let current = realm::current();
        let use_case = family_static(family);
        let issued = tokio::task::spawn_blocking(move || {
            realm::run_sync(current, || {
                authority.issue_enrolled(&scope, use_case, &spec)
            })
        })
        .await;
        let issued = match issued {
            Ok(Ok(i)) => i,
            Ok(Err(r)) => {
                return Err(self.audit_refusal(
                    family,
                    asked,
                    Refusal::new(
                        r.code,
                        503,
                        format!(
                            "The {} Issuing CA could not issue: {}",
                            family_label(family),
                            r.errors
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "unknown reason".into())
                        ),
                    ),
                ))
            }
            Err(e) => {
                return Err(self.audit_refusal(
                    family,
                    asked,
                    Refusal::new(
                        codes::STS_ENROLL_0042,
                        503,
                        format!(
                            "The {} Issuing CA could not issue: {}",
                            family_label(family),
                            e
                        ),
                    ),
                ))
            }
        };
        let cert =
            sts_pki::x509::read::Certificate::from_der(&issued.certificate_der)
                .ok();
        let thumbprint = sts_pki::der::hex(
            &sts_crypto::jws_alg::Hash::Sha256.digest(&issued.certificate_der),
        );
        let subject_dn = cert
            .as_ref()
            .map(|c| dn_rfc4514(&c.subject_der))
            .unwrap_or_default();
        let record = json!({
            "serialHex": normal_serial(&issued.serial_hex),
            "family": family,
            "profile": profile,
            "subject": if subject_dn.is_empty() { issued.subject.clone() } else { subject_dn.clone() },
            "names": names.iter().map(|(k, v)| format!("{}:{}", k, v)).collect::<Vec<_>>(),
            "thumbprint": thumbprint,
            "keyAlg": asked.key_alg,
            "notBefore": issued.not_before,
            "notAfter": issued.not_after,
            "issuedAt": iso(now),
            "requestedBy": asked.principal.as_ref().map(Principal::requested_by),
            "via": if asked.via.is_empty() { family.to_string() } else { asked.via.clone() },
            "keySource": if asked.key_source == "server" { "server" } else { "client" },
            "replaces": if replacing.is_empty() { Json::Null } else { Json::from(replacing.clone()) },
            "certificatePem": issued.certificate_pem,
            "chainPem": issued.issuer_chain_pem,
        });
        let serial = str_of(&record, "serialHex").to_string();
        let kind = resolved.entry.kind.clone();
        if asked.key_source == "server" {
            let label = if kind == "person" {
                "person-private-key"
            } else {
                "application-private-key"
            };
            let Some(sealed) = self.seal_text(
                &asked.private_key_pem,
                label,
                if kind == "person" { "cell" } else { "" },
            ) else {
                return Err(self.audit_refusal(
                    family,
                    asked,
                    Refusal::new(
                        codes::STS_ENROLL_0043,
                        503,
                        "The generated private key could not be sealed for storage, so the \
                         certificate was not recorded.",
                    ),
                ));
            };
            let prefix = format!("{}:", serial);
            let mut keys: Vec<String> = resolved
                .held("privateKey")
                .into_iter()
                .filter(|one| !one.starts_with(&prefix))
                .collect();
            keys.push(format!("{}{}", prefix, sealed));
            if !self.write_attribute(&resolved.entry, "privateKey", &keys) {
                return Err(self.audit_refusal(
                    family,
                    asked,
                    Refusal::new(
                        codes::STS_ENROLL_0041,
                        503,
                        format!(
                            "The generated private key could not be written onto the {}.",
                            resolved.entry.label()
                        ),
                    ),
                ));
            }
        }
        let mut kept: Vec<String> = existing
            .iter()
            .filter(|one| {
                ms_of(str_of(one, "notAfter")) > now
                    || one
                        .get("revoked")
                        .is_some_and(|r| !r.is_null() && r != &json!(false))
            })
            .map(stringify)
            .collect();
        kept.push(stringify(&record));
        if !self.write_attribute(&resolved.entry, "certificate", &kept) {
            return Err(self.audit_refusal(
                family,
                asked,
                Refusal::new(
                    codes::STS_ENROLL_0041,
                    503,
                    format!(
                        "The certificate was issued but could not be written onto the {}.",
                        resolved.entry.label()
                    ),
                ),
            ));
        }
        if kind == "person" && !subject_dn.is_empty() {
            let mut subjects = resolved.attributes.values("x509subject");
            if !subjects.contains(&subject_dn) {
                subjects.push(subject_dn.clone());
                let _written = self.d.entries.write(
                    "person",
                    &resolved.entry.id,
                    "x509subject",
                    &subjects,
                );
            }
        }
        self.d.audit.record(&json!({
            "category": "protocol", "action": "enrollment.issue",
            "protocol": family_label(family), "outcome": "success",
            "actor": asked.principal.as_ref().map(|p| p.id.clone()).unwrap_or_default(),
            "target": resolved.entry.uri(),
            "summary": format!("a {} certificate was issued over {} for the {}{}", profile,
                family_label(family), resolved.entry.label(),
                if admin { " by an administrator" } else { "" }),
            "detail": { "serialHex": serial, "profile": profile,
                        "keySource": record["keySource"], "via": record["via"],
                        "notAfter": record["notAfter"] },
        }));
        self.d.signals.certificate_changed(&json!({
            "username": if kind == "person" { resolved.entry.id.clone() } else { String::new() },
            "application": if kind == "application" { resolved.entry.id.clone() } else { String::new() },
            "pem": record["certificatePem"], "changeType": "create",
            "friendlyName": format!("{} certificate", profile),
            "initiatingEntity": if admin { "admin" } else { "user" },
            "via": family_label(family),
        }));
        if !replacing.is_empty() {
            let by = asked
                .principal
                .as_ref()
                .map(|p| p.id.clone())
                .unwrap_or_default();
            if let Err(superseded) = self.revoke_enrolled(
                &replacing,
                "superseded",
                &by,
                None,
                None,
                true,
            ) {
                let undone = self.revoke_enrolled(
                    &serial,
                    "cessationOfOperation",
                    &by,
                    None,
                    None,
                    true,
                );
                tracing::error!(
                    "{}cert_enrollment: the certificate serial {} could not be superseded by \
                     its renewal {} ({}); the renewal {} and the request refused.",
                    sts_core::log::tag(codes::STS_ENROLL_0093.as_str()),
                    replacing,
                    serial,
                    superseded.sentence,
                    if undone.is_ok() { "was revoked" } else { "could NOT be revoked either" }
                );
                return Err(self.audit_refusal(
                    family,
                    asked,
                    Refusal::new(
                        codes::STS_ENROLL_0093,
                        503,
                        "The certificate this request renews could not be revoked, so the \
                         renewal was taken back; try again.",
                    ),
                ));
            }
        }
        Ok(Issued {
            record: public_record(&record),
            target: resolved.entry,
            admin,
            private_key_pem: String::new(),
        })
    }

    /// `issueWithServerKey(spec)`: a key pair generated here, then issued.
    #[tracing::instrument(level = "debug", skip(self, asked))]
    pub async fn issue_with_server_key(
        &self,
        asked: &IssueSpec,
    ) -> Outcome<Issued> {
        let key_alg = if asked.key_alg.is_empty() {
            "ec-p256".to_string()
        } else {
            asked.key_alg.clone()
        };
        let ids = sts_pki::authority::catalog::key_alg_ids();
        let Some(alg) = ids
            .contains(&key_alg)
            .then(|| sts_pki::authority::catalog::key_alg(&key_alg))
            .flatten()
        else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0035,
                400,
                format!(
                    "\"{}\" is not a key algorithm this service generates. They are {}.",
                    key_alg,
                    ids.join(", ")
                ),
            ));
        };
        let generated =
            tokio::task::spawn_blocking(move || alg.generate()).await;
        let Ok(Ok((private_pem, public_pem))) = generated else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0035,
                400,
                format!("A {} key pair could not be generated.", key_alg),
            ));
        };
        let mut spec = asked.clone();
        spec.public_key_pem = public_pem;
        spec.key_source = "server".into();
        spec.private_key_pem = private_pem.clone();
        spec.key_alg = key_alg;
        let mut issued = self.issue(&spec).await?;
        issued.private_key_pem = private_pem;
        Ok(issued)
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn seal_text(
        &self,
        plain: &str,
        label: &str,
        tier: &str,
    ) -> Option<String> {
        if !self.d.keystore.persists() {
            return Some(plain.to_string());
        }
        self.d.keystore.seal(plain, label, tier)
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn open_text(&self, value: &str, label: &str) -> Option<String> {
        if !sts_crypto::secrets::is_encrypted_with_kek(value) {
            return Some(value.to_string());
        }
        self.d.keystore.open(value, label)
    }

    /// `enrolledOf(entry)`: the certificates on an entry, newest first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enrolled_of(&self, entry: &Entry) -> Vec<Json> {
        let Some(values) = self.read_attribute(entry, "certificate") else {
            return Vec::new();
        };
        let mut out = enrolled_from(&values, None);
        out.sort_by(|a, b| str_of(b, "issuedAt").cmp(str_of(a, "issuedAt")));
        out
    }

    /// `findEnrolled(serialHex, family)`: the entry holding an enrolled
    /// certificate, found through the authority's register.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn find_enrolled(
        &self,
        serial: &str,
        family: Option<&str>,
    ) -> Option<Found> {
        let wanted = normal_serial(serial);
        if wanted.is_empty() {
            return None;
        }
        let families: Vec<&str> = match family {
            Some(f) => vec![f],
            None => FAMILIES.to_vec(),
        };
        for f in families {
            let issued = self
                .d
                .authority
                .issued_key_pairs_for(&realm::current_id(), f);
            let Some(hit) = issued
                .iter()
                .find(|one| normal_serial(str_of(one, "serialHex")) == wanted)
            else {
                continue;
            };
            let kind = str_of(hit, "subjectKind");
            if kind != "person" && kind != "application" {
                continue;
            }
            let holder = str_of(hit, "holderSubject");
            let renamed = if holder.is_empty() {
                str_of(hit, "identifier").to_string()
            } else {
                self.d.entries.name_for_subject(holder)
            };
            if renamed.is_empty() {
                return None;
            }
            let entry = Entry::new(kind, &renamed);
            if let Some(record) = self
                .enrolled_of(&entry)
                .into_iter()
                .find(|one| normal_serial(str_of(one, "serialHex")) == wanted)
            {
                return Some(Found {
                    entry,
                    record,
                    family: f.to_string(),
                });
            }
        }
        None
    }

    /// `revokeEnrolled(serialHex, reason, by, { entry, family, quiet })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revoke_enrolled(
        &self,
        serial: &str,
        reason: &str,
        by: &str,
        entry: Option<&Entry>,
        family: Option<&str>,
        quiet: bool,
    ) -> Outcome<Found> {
        let Some(found) = self.find_enrolled(serial, family) else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0070,
                404,
                format!(
                    "No certificate with that serial was issued over {} in this realm.",
                    family.map(family_label).unwrap_or("an enrollment protocol")
                ),
            ));
        };
        if let Some(e) = entry {
            if *e != found.entry {
                return Err(Refusal::new(
                    codes::STS_ENROLL_0071,
                    403,
                    format!(
                        "That certificate does not belong to the {}.",
                        e.label()
                    ),
                ));
            }
        }
        let reason = if reason.is_empty() {
            "unspecified"
        } else {
            reason
        };
        let note = format!(
            "enrolled over {} for {}{}",
            family_label(&found.family),
            found.entry.uri(),
            if by.is_empty() {
                String::new()
            } else {
                format!("; revoked by {}", by)
            }
        );
        if let Err(r) = self.d.authority.revoke(
            &realm::current_id(),
            &found.family,
            str_of(&found.record, "serialHex"),
            Some(reason),
            str_of(&found.record, "subject"),
            &note,
        ) {
            return Err(Refusal::new(
                r.code,
                400,
                r.errors
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "The revocation was refused.".into()),
            ));
        }
        let values = self
            .read_attribute(&found.entry, "certificate")
            .unwrap_or_default();
        let at = iso(now_ms());
        let wanted = normal_serial(str_of(&found.record, "serialHex"));
        let rewritten: Vec<String> = parse_json_values(&values)
            .into_iter()
            .map(|mut one| {
                let revoked = one
                    .get("revoked")
                    .is_some_and(|r| !r.is_null() && r != &json!(false));
                if normal_serial(str_of(&one, "serialHex")) == wanted
                    && !revoked
                {
                    one["revoked"] =
                        json!({ "at": at, "reason": reason, "by": by });
                }
                stringify(&one)
            })
            .collect();
        let _written =
            self.write_attribute(&found.entry, "certificate", &rewritten);
        let kind = found.entry.kind.as_str();
        if kind == "person" || kind == "application" {
            let initiating = if reason == "superseded" {
                "system"
            } else if by == found.entry.id {
                "user"
            } else {
                "admin"
            };
            self.d.signals.certificate_changed(&json!({
                "username": if kind == "person" { found.entry.id.clone() } else { String::new() },
                "application": if kind == "application" { found.entry.id.clone() } else { String::new() },
                "pem": found.record["certificatePem"], "changeType": "revoke",
                "friendlyName": format!("{} certificate", str_of(&found.record, "profile")),
                "initiatingEntity": initiating, "via": family_label(&found.family),
            }));
            if reason == "keyCompromise" {
                self.d.signals.credential_compromised(&json!({
                    "username": if kind == "person" { found.entry.id.clone() } else { String::new() },
                    "credentialType": "x509",
                    "via": family_label(&found.family),
                }));
            }
        }
        if !quiet {
            self.d.audit.record(&json!({
                "category": "protocol", "action": "enrollment.revoke",
                "protocol": family_label(&found.family), "outcome": "success",
                "actor": by, "target": found.entry.uri(),
                "summary": format!("an enrolled certificate was revoked ({})", reason),
                "detail": { "serialHex": found.record["serialHex"], "family": found.family },
            }));
        }
        Ok(found)
    }

    /// `serverKeyOf(entry, serialHex)`: a server-generated private key,
    /// opened — for the entry's own holder.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn server_key_of(&self, entry: &Entry, serial: &str) -> Option<String> {
        let prefix = format!("{}:", normal_serial(serial));
        let hit = self
            .read_attribute(entry, "privateKey")
            .unwrap_or_default()
            .into_iter()
            .find(|one| one.starts_with(&prefix))?;
        let label = if entry.kind == "person" {
            "person-private-key"
        } else {
            "application-private-key"
        };
        self.open_text(&hit[prefix.len()..], label)
    }

    /// `certificatesInRealm(family)`: newest first, each with its entry.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn certificates_in_realm(&self, family: Option<&str>) -> Vec<Json> {
        let mut out = Vec::new();
        for kind in ["person", "application"] {
            for (id, values) in self.d.entries.holders_with_values(
                kind,
                super::attribute(kind, "certificate"),
            ) {
                let entry = Entry::new(kind, &id);
                for record in enrolled_from(&values, family) {
                    let mut row = json!({ "entry": entry.to_json(), "entryUri": entry.uri() });
                    if let (Some(r), Some(o)) =
                        (row.as_object_mut(), record.as_object())
                    {
                        for (k, v) in o {
                            r.insert(k.clone(), v.clone());
                        }
                    }
                    out.push(row);
                }
            }
        }
        out.sort_by(|a, b| str_of(b, "issuedAt").cmp(str_of(a, "issuedAt")));
        out
    }

    /// `certificateCountsInRealm(family)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn certificate_counts_in_realm(&self, family: Option<&str>) -> Json {
        let (mut held, mut valid, mut revoked, mut expired) = (0, 0, 0, 0);
        for kind in ["person", "application"] {
            for (_, values) in self.d.entries.holders_with_values(
                kind,
                super::attribute(kind, "certificate"),
            ) {
                for record in enrolled_from(&values, family) {
                    held += 1;
                    match str_of(&record, "status") {
                        "valid" => valid += 1,
                        "revoked" => revoked += 1,
                        _ => expired += 1,
                    }
                }
            }
        }
        json!({ "held": held, "valid": valid, "revoked": revoked, "expired": expired })
    }
}

/// The family as the `'static` use case id the authority takes.
fn family_static(family: &str) -> &'static str {
    match family {
        "acme" => "acme",
        "est" => "est",
        _ => "scep",
    }
}

/// `findEnrolled()`'s answer.
#[derive(Debug, Clone)]
pub struct Found {
    pub entry: Entry,
    pub record: Json,
    pub family: String,
}
