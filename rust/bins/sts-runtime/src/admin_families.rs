// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE FAMILIES' ACTS ON `/admin-api` IN THE RUNTIME (rule 7): the
//! certificate authority's (`admin-ui/pki_admin.ts`'s `pkiAction()`) and
//! ACME's, EST's and SCEP's (`acme_console.ts`, `est_console.ts`,
//! `scep_console.ts`), answered by `sts-pki`'s authority and
//! `sts-enroll`'s core — both made once the store is open, so they are
//! handed over by [`AdminFamilies::install`] when the router is built.
//!
//! PORTED: `pki/build` (the realm's branch built, `buildScope()`),
//! `pki/revoke-certificate` and `pki/release-hold`; ACME's `create-eab`,
//! `delete-eab`, `revoke-certificate`, `add-host-name` and
//! `remove-host-name`; EST's `revoke-certificate`, `add-host-name` and
//! `remove-host-name`; SCEP's `create-challenge`, `delete-challenge`,
//! `revoke-certificate`, `add-host-name` and `remove-host-name`. An
//! unknown action of the three enrollment routes is refused in its
//! family's words.
//!
//! NOT PORTED, and what is left out of a ported act's answer: the
//! enrollment monitors' rows (`monitor.record()`), the Shared Signals a
//! revocation sends (`accountSignals`, `serviceSignals.caRevoked()`), the
//! re-minting of a realm's own signing-key certificates after a build
//! (`recertifyScope()`: the answer says none were), and the console's form
//! fields beyond a build's organisation, country, algorithms and years.

use std::sync::{Arc, OnceLock};

use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm;
use sts_enroll::core::{Entry, Refusal};
use sts_mgmt_api::families::{Asked, FamilyPorts};
use sts_mgmt_api::setup::Answered;
use sts_pki::authority::hierarchy::BuildOptions;
use sts_pki::authority::Authority;

/// The authority and the enrollment families, once made.
#[derive(Default)]
pub struct AdminFamilies {
    authority: OnceLock<Arc<Authority>>,
    enroll: OnceLock<Arc<sts_enroll::wiring::Families>>,
    registry: OnceLock<Arc<sts_core::realm::RealmRegistry>>,
}

fn ok(body: Json) -> Answered {
    Answered {
        status: 200,
        body,
        code: None,
    }
}

fn refused(code: ErrorCode, errors: Vec<String>) -> Answered {
    Answered {
        status: 400,
        body: json!({ "ok": false, "errors": errors }),
        code: Some(code),
    }
}

/// `handedOn(refusal, fallback)`: the core's refusal, its HTTP status
/// dropped.
fn handed_on(r: &Refusal) -> Answered {
    refused(r.code, vec![r.sentence.clone()])
}

fn text(body: &Json, key: &str) -> String {
    match body.get(key) {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.trim().to_string(),
        Some(other) => other.to_string(),
    }
}

fn entry_of(body: &Json) -> Entry {
    Entry::new(&text(body, "kind"), &text(body, "identifier"))
}

/// `actorOf()` / `consoleActorOf()`: the caller the gate let in, or
/// `admin-api` where no token was asked for.
fn actor_of(asked: &Asked<'_>) -> String {
    asked
        .caller
        .map(|c| c.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "admin-api".to_string())
}

impl AdminFamilies {
    /// The authority and the families, handed over by the composition root
    /// when it builds the router.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn install(
        &self,
        authority: Arc<Authority>,
        enroll: Arc<sts_enroll::wiring::Families>,
        registry: Arc<sts_core::realm::RealmRegistry>,
    ) {
        if self.authority.set(authority).is_err()
            || self.enroll.set(enroll).is_err()
            || self.registry.set(registry).is_err()
        {
            tracing::debug!("admin-api: the families were installed already.");
        }
    }

    /// `scopeFrom(body)`: the scope a body names, else the ambient realm.
    fn scope_from(body: &Json) -> String {
        let asked = text(body, "scope");
        if !asked.is_empty() && asked != "default" {
            return asked;
        }
        realm::current_id()
    }

    fn pki(&self, a: &Authority, asked: &Asked<'_>) -> Option<Answered> {
        let body = asked.body;
        let label = realm::current().name.clone();
        let label = if label.is_empty() {
            realm::current_id()
        } else {
            label
        };
        match asked.operation_id {
            "buildPkiChain" => {
                let mut options = BuildOptions::from_json(body);
                if options.organisation.is_none() {
                    let org = a.config().organisation_or_default();
                    options.organisation = Some(org);
                }
                let scope = Self::scope_from(&json!({}));
                Some(match a.build_scope(&scope, &options) {
                    Err(r) => refused(r.code, vec![r.sentence()]),
                    Ok(_) => ok(json!({
                        "ok": true,
                        "why": format!(
                            "A three-tier certificate authority was built for the \"{}\" realm, and 0 \
                             certificate(s) this realm's own signing keys publish were re-minted from it. \
                             Anything else issued from a PREVIOUS hierarchy now chains to nothing — this \
                             service keeps no copy of what it issued, so none of it can be listed.",
                            label
                        ),
                        "chain": describe_chain(a, &scope),
                    })),
                })
            }
            "revokePkiCertificate" => {
                let scope = Self::scope_from(body);
                let ca = text(body, "ca");
                let reason = text(body, "reason");
                Some(
                    match a.revoke(
                        &scope,
                        &ca,
                        &text(body, "serialHex"),
                        Some(if reason.is_empty() {
                            "superseded"
                        } else {
                            &reason
                        }),
                        &text(body, "subject"),
                        &text(body, "note"),
                    ) {
                        Err(r) => refused(r.code, vec![r.sentence()]),
                        Ok(done) => {
                            let e = &done.entry;
                            let why = if done.already {
                                format!(
                                    "That certificate was already revoked, at {}, for \"{}\". The entry is \
                                     unchanged: a validator is entitled to act on the first moment it was \
                                     told about, and moving the date forward would be this service saying \
                                     the certificate was valid for longer than it claimed.",
                                    text(e, "revokedAt"),
                                    text(e, "reason")
                                )
                            } else {
                                format!(
                                    "Certificate {} is on the \"{}\" authority's revocation list as \"{}\". \
                                     Its CRL and its OCSP responder say so from now on. NOTHING ELSE CHANGED: \
                                     whoever holds that key still holds it, the certificate still chains, and \
                                     this service does not consult its own lists — so what this buys is that \
                                     a relying party which DOES check can now find out.",
                                    text(e, "serialHex"),
                                    ca,
                                    text(e, "reason")
                                )
                            };
                            ok(json!({ "ok": true, "entry": e,
                                       "already": done.already, "why": why }))
                        }
                    },
                )
            }
            "releasePkiCertificateHold" => {
                let scope = Self::scope_from(body);
                let serial = text(body, "serialHex");
                Some(match a.release(&scope, &text(body, "ca"), &serial) {
                    Err(r) => refused(r.code, vec![r.sentence()]),
                    Ok(()) => ok(json!({ "ok": true, "why": format!(
                        "The hold on {} is lifted and the serial is off that authority's list. A validator \
                         that cached the previous CRL will go on calling it revoked until that copy expires, \
                         which is pki.crlLifetimeMinutes — a hold is the only reason RFC 5280 lets you undo, \
                         and even then the undoing is not instantaneous anywhere but here.",
                        serial) })),
                })
            }
            _ => None,
        }
    }

    fn acme(
        &self,
        f: &sts_enroll::wiring::Families,
        asked: &Asked<'_>,
    ) -> Option<Answered> {
        const ACTIONS: [&str; 6] = [
            "create-eab",
            "delete-eab",
            "deactivate-account",
            "revoke-certificate",
            "add-host-name",
            "remove-host-name",
        ];
        let body = asked.body;
        let actor = actor_of(asked);
        let core = &f.core;
        Some(match asked.action {
            "create-eab" => {
                let target = entry_of(body);
                let lifetime = body.get("lifetimeS").and_then(Json::as_i64);
                match core.create_eab(&target, lifetime, &actor) {
                    Err(r) => handed_on(&r),
                    Ok(made) => {
                        let directory =
                            format!("{}/enroll/acme/directory", asked.base);
                        ok(json!({
                            "ok": true,
                            "kid": made.kid,
                            "hmacKey": made.hmac_key,
                            "alg": made.alg,
                            "expiresAt": made.expires_at,
                            "target": made.target.to_json(),
                            "targetUri": made.target.uri(),
                            "directory": directory,
                            "certbot": format!(
                                "certbot register --server {} --eab-kid {} --eab-hmac-key {} --agree-tos \
                                 --no-eff-email --register-unsafely-without-email",
                                directory, made.kid, made.hmac_key
                            ),
                            "message": format!(
                                "An External Account Binding key was created for the {}. The HMAC key is \
                                 shown once and cannot be read back.",
                                made.target.label()
                            ),
                        }))
                    }
                }
            }
            "delete-eab" => {
                let kid = text(body, "kid");
                match core.delete_eab(&kid, &actor) {
                    Err(r) => handed_on(&r),
                    Ok(_) => ok(json!({ "ok": true, "kid": kid,
                        "message": format!(
                            "The External Account Binding key {} is deleted. An account it already bound \
                             keeps its binding.", kid) })),
                }
            }
            "revoke-certificate" => {
                let serial = text(body, "serial");
                let Some(found) = core.find_enrolled(&serial, Some("acme"))
                else {
                    return Some(refused(
                        codes::STS_ACME_0093,
                        vec![format!(
                            "No certificate with serial {} was issued over ACME in this realm.",
                            serial
                        )],
                    ));
                };
                if found
                    .record
                    .get("revoked")
                    .is_some_and(|r| !r.is_null() && r != &json!(false))
                {
                    return Some(refused(
                        codes::STS_ACME_0096,
                        vec!["That certificate is already revoked.".into()],
                    ));
                }
                let reason = match text(body, "reason") {
                    r if r.is_empty() => "unspecified".to_string(),
                    r => r,
                };
                let serial_hex = text(&found.record, "serialHex");
                match core.revoke_enrolled(
                    &serial_hex,
                    &reason,
                    &actor,
                    None,
                    Some("acme"),
                    false,
                ) {
                    Err(r) => handed_on(&r),
                    Ok(_) => ok(json!({ "ok": true, "serialHex": serial_hex,
                        "reason": reason,
                        "message": format!(
                            "The certificate {} is revoked ({}) and on the ACME Issuing CA's CRL.",
                            serial_hex, reason) })),
                }
            }
            "add-host-name" | "remove-host-name" => {
                let add = asked.action == "add-host-name";
                let entry = entry_of(body);
                let host = text(body, "hostName");
                let before = core.change_host_name(&entry, &host, add, &actor);
                match before {
                    Err(r) => handed_on(&r),
                    Ok(names) => ok(json!({ "ok": true, "hostNames": names,
                        "entryUri": entry.uri(),
                        "message": format!(
                            "The host names of {} are now: {}.",
                            entry.uri(),
                            if names.is_empty() { "none".to_string() }
                            else { names.join(", ") }) })),
                }
            }
            "deactivate-account" => return None,
            other => refused(
                codes::STS_ACME_0090,
                vec![format!(
                    "Unknown action \"{}\". The six are: {}.",
                    other.chars().take(60).collect::<String>(),
                    ACTIONS.join(", ")
                )],
            ),
        })
    }

    fn est(
        &self,
        f: &sts_enroll::wiring::Families,
        asked: &Asked<'_>,
    ) -> Option<Answered> {
        const ACTIONS: [&str; 4] = [
            "issue-server-key",
            "revoke-certificate",
            "add-host-name",
            "remove-host-name",
        ];
        let body = asked.body;
        let actor = actor_of(asked);
        let core = &f.core;
        Some(match asked.action {
            "revoke-certificate" => {
                let reason = match text(body, "reason") {
                    r if r.is_empty() => "unspecified".to_string(),
                    r => r,
                };
                match core.revoke_enrolled(
                    &text(body, "serial"),
                    &reason,
                    &actor,
                    None,
                    Some("est"),
                    false,
                ) {
                    Err(r) => refused(r.code, vec![r.sentence.clone()]),
                    Ok(found) => {
                        let serial_hex = text(&found.record, "serialHex");
                        ok(json!({ "ok": true, "serialHex": serial_hex,
                            "reason": reason, "entry": found.entry.to_json(),
                            "message": format!(
                                "The EST certificate {} of {} is revoked ({}) and on the EST Issuing CA's \
                                 CRL.", serial_hex, found.entry.uri(), reason) }))
                    }
                }
            }
            "add-host-name" | "remove-host-name" => {
                let add = asked.action == "add-host-name";
                let entry = entry_of(body);
                let host = text(body, "hostName");
                match core.change_host_name(&entry, &host, add, &actor) {
                    Err(r) => refused(r.code, vec![r.sentence.clone()]),
                    Ok(names) => ok(json!({ "ok": true, "hostNames": names,
                        "message": format!(
                            "The host name {} was {}{}.", host,
                            if add { "registered on " } else { "removed from " },
                            entry.uri()) })),
                }
            }
            "issue-server-key" => return None,
            other => refused(
                codes::STS_EST_0032,
                vec![format!(
                    "Unknown action \"{}\". The four are: {}.",
                    other.chars().take(60).collect::<String>(),
                    ACTIONS.join(", ")
                )],
            ),
        })
    }

    fn scep(
        &self,
        a: &Authority,
        f: &sts_enroll::wiring::Families,
        asked: &Asked<'_>,
    ) -> Option<Answered> {
        const ACTIONS: [&str; 6] = [
            "create-challenge",
            "delete-challenge",
            "reissue-ra",
            "revoke-certificate",
            "add-host-name",
            "remove-host-name",
        ];
        let body = asked.body;
        let actor = asked.caller.map(|c| c.name.clone()).unwrap_or_default();
        let core = &f.core;
        Some(match asked.action {
            "create-challenge" => {
                let target = entry_of(body);
                let profile = text(body, "profile");
                let lifetime = body.get("lifetimeS").and_then(Json::as_i64);
                match core.create_scep_challenge(
                    &target,
                    Some(profile.as_str()).filter(|p| !p.is_empty()),
                    lifetime,
                    &actor,
                ) {
                    Err(r) => refused(r.code, vec![r.sentence.clone()]),
                    Ok(made) => {
                        let url = format!(
                            "{}/enroll/scep/{}",
                            asked.base, made.profile
                        );
                        let plain = format!(
                            "{}{}/enroll/scep/{}",
                            a.config().distribution.http_base(),
                            self.registry
                                .get()
                                .map(|r| r.current_prefix())
                                .unwrap_or_default(),
                            made.profile
                        );
                        let (organisation, country) = core.organisation_of();
                        let hint = [
                            format!("sscep getca -u {} -c ca.crt", plain),
                            format!(
                                "openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr \
                                 -addext \"subjectAltName=URI:{}\" -config <(printf \"[req]\\nprompt=no\\n\
                                 distinguished_name=dn\\nattributes=a\\n[dn]\\nCN={}\\nO={}{}\\n[a]\\n\
                                 challengePassword={}\\n\")",
                                made.target.uri(),
                                made.target.id,
                                organisation,
                                if country.is_empty() {
                                    String::new()
                                } else {
                                    format!("\\nC={}", country)
                                },
                                made.challenge
                            ),
                            format!(
                                "sscep enroll -u {} -c ca.crt-0 -e ca.crt-0 -k key.pem -r req.csr -l cert.pem \
                                 -S sha256 -E aes",
                                plain
                            ),
                        ]
                        .join("\n");
                        ok(json!({
                            "ok": true, "id": made.id,
                            "challenge": made.challenge,
                            "profile": made.profile,
                            "expiresAt": made.expires_at,
                            "target": made.target.to_json(),
                            "entryUri": made.target.uri(),
                            "url": url, "plainUrl": plain, "hint": hint,
                            "message": format!(
                                "A challenge password was created for {} ({}). It is shown once.",
                                made.target.uri(), made.profile),
                        }))
                    }
                }
            }
            "delete-challenge" => {
                let id = text(body, "id");
                match core.delete_scep_challenge(&id, &actor) {
                    Err(r) => refused(r.code, vec![r.sentence.clone()]),
                    Ok(entry) => ok(json!({ "ok": true, "id": id,
                        "entryUri": entry.uri(),
                        "message": format!("The challenge {} is deleted.", id) })),
                }
            }
            "revoke-certificate" => {
                let reason = match text(body, "reason") {
                    r if r.is_empty() => "unspecified".to_string(),
                    r => r,
                };
                match core.revoke_enrolled(
                    &text(body, "serial"),
                    &reason,
                    &actor,
                    None,
                    Some("scep"),
                    false,
                ) {
                    Err(r) => refused(r.code, vec![r.sentence.clone()]),
                    Ok(found) => {
                        let serial_hex = text(&found.record, "serialHex");
                        ok(json!({ "ok": true, "serialHex": serial_hex,
                            "entryUri": found.entry.uri(), "reason": reason,
                            "message": format!(
                                "Certificate {} is revoked ({}) and on the SCEP Issuing CA's CRL.",
                                serial_hex, reason) }))
                    }
                }
            }
            "add-host-name" | "remove-host-name" => {
                let add = asked.action == "add-host-name";
                let entry = entry_of(body);
                match core.change_host_name(
                    &entry,
                    &text(body, "hostName"),
                    add,
                    &actor,
                ) {
                    Err(r) => refused(r.code, vec![r.sentence.clone()]),
                    Ok(names) => ok(json!({ "ok": true,
                        "entryUri": entry.uri(), "hostNames": names,
                        "message": format!(
                            "The host names of {} are now {}.", entry.uri(),
                            if names.is_empty() { "none".to_string() }
                            else { names.join(", ") }) })),
                }
            }
            "reissue-ra" => return None,
            other => refused(
                codes::STS_SCEP_0062,
                vec![format!(
                    "Unknown action \"{}\". The {} are: {}.",
                    other,
                    ACTIONS.len(),
                    ACTIONS.join(", ")
                )],
            ),
        })
    }
}

/// `TIERS`' `what`, in order.
const TIER_WHAT: [&str; 3] = [
    "The trust anchor. Self-signed, the longest-lived of the three, and the only certificate in the \
     hierarchy a relying party has to be given out of band — everything below it travels in the chain.",
    "Signed by the Root. It exists so that the Root's key can be used once and then left alone: a \
     compromise here is repaired by reissuing this tier, and a compromise of the Root is not repaired at \
     all. pathLen is 1, so it may sign one more CA and no deeper.",
    "Signed by the Intermediate, and the only tier that signs anything this service hands out. pathLen is \
     0 — it signs LEAVES and no further CA, which is what makes \"an application certificate cannot be used \
     to mint another\" a property of the encoding rather than of this service's manners.",
];

/// `describeChain(rawChainFor(scope))`: the hierarchy with no private key.
fn describe_chain(a: &Authority, scope: &str) -> Json {
    let Some(tiers) = a.raw_chain_for(scope) else {
        return Json::Null;
    };
    let row = a.raw_row_for(scope).unwrap_or(Json::Null);
    let now = chrono::Utc::now().timestamp_millis();
    let null_if_empty = |v: &Json| match v {
        Json::String(t) if t.is_empty() => Json::Null,
        Json::Null => Json::Null,
        other => other.clone(),
    };
    json!({
        "realm": row["realm"],
        "createdAt": row["createdAt"],
        "keyAlg": row["keyAlg"],
        "signatureAlg": row["signatureAlg"],
        "altKeyAlg": null_if_empty(&row["altKeyAlg"]),
        "organisation": row["organisation"],
        "country": row["country"],
        "issuedCount": row["issuedCount"].as_i64().unwrap_or(0),
        "persisted": a.persists(),
        "tiers": tiers.iter().enumerate().map(|(i, one)| {
            let expired = chrono::DateTime::parse_from_rfc3339(
                one["notAfter"].as_str().unwrap_or(""),
            )
            .map(|t| t.timestamp_millis() < now)
            .unwrap_or(false);
            json!({
                "tier": one["tier"], "label": one["label"],
                "what": TIER_WHAT.get(i).copied().unwrap_or(""),
                "subject": one["subject"], "serialHex": one["serialHex"],
                "notBefore": one["notBefore"], "notAfter": one["notAfter"],
                "keyAlg": one["keyAlg"], "signatureAlg": one["signatureAlg"],
                "altKeyAlg": null_if_empty(&one["altKeyAlg"]),
                "altSignatureAlg": null_if_empty(&one["altSignatureAlg"]),
                "thumbprint": one["thumbprint"],
                "certificatePem": one["certificatePem"],
                "expired": expired,
            })
        }).collect::<Vec<_>>(),
    })
}

impl FamilyPorts for AdminFamilies {
    fn answer(&self, asked: &Asked<'_>) -> Option<Answered> {
        let authority = self.authority.get()?;
        match asked.family {
            "pki" => self.pki(authority, asked),
            "acme" => self.acme(self.enroll.get()?, asked),
            "est" => self.est(self.enroll.get()?, asked),
            "scep" => self.scep(authority, self.enroll.get()?, asked),
            _ => None,
        }
    }
}
