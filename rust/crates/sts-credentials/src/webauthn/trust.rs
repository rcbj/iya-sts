// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE TRUST HALF OF AN ATTESTATION: `authn/webauthn_attestation.ts`'s
//! `assess()` (#105) — WebAuthn Level 3 section 7.1 steps 21 to 25 under
//! the realm's attestation policy — and the record a key carries of it.
//!
//!   21-22. the statement, by [`super::attestation::verify_statement`];
//!   23.    the model the FIDO Metadata Service lists for it, by AAGUID or
//!          by attestation key identifier ([`Metadata`]), refused outright
//!          where ANY status report ever said it was compromised;
//!   24.    the trust path from the attestation certificate to an anchor —
//!          `webauthn.attestationTrustAnchors` and the roots MDS lists for
//!          the model — with a listed model's chain REQUIRED to reach MDS's
//!          roots, revocation asked of the anchored chain ([`Revocation`],
//!          `revocation_status.verdictFor()`, a certificate that names no
//!          distribution point excepted), and an `android-key` chain asked
//!          of Google's status list ([`AndroidStatus`], #256);
//!   25.    what the policy and the settings that DEMAND trust refuse: a
//!          statement that did not chain, an AAGUID not on the list, a
//!          certification level or FIPS the model does not hold.
//!
//! What `attestationTrusted` and the AAGUID decide is here too: an AAGUID
//! allow-list, a level, FIPS, a bound serial (#532) and an attestation
//! algorithm list (#941) each DEMAND a trusted statement, because an AAGUID
//! in authenticator data is otherwise the authenticator's say-so; the
//! record's `trusted` is what a sign-in's policy reads afterwards.
//!
//! WHAT REPLACED WHAT. Node's `WebauthnAttestationDeps` (the policy, the
//! lazily required metadata, revocation and Android modules, the clock) are
//! [`AttestationPorts`]. The one validation door (`certificate_trust.ts`,
//! #1360) is asked through [`AttestationPorts::paranoid_path`]: not in
//! force (development's `pki.paranoid=auto`, and the default here) it IS
//! `sts-pki`'s `verify_path_to_anchors()`, which is what this module calls.
//! Node awaits the lookups; here each port answers in turn, and a port that
//! fails (`Err`) is a refusal with STS-AUTHN-0241, where Node's `assess()`
//! catches what threw.

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jws_alg::Hash;
use sts_crypto::webauthn::cose_signature_alg;
use sts_pki::attestation::{
    attestation_device_serial, attestation_signature_algorithm,
    certificate_serial_hex,
};
use sts_pki::foreign::{attestation_key_identifier, certificate_bundle};
use sts_pki::path::{verify_path_to_anchors, Entry, PathOptions};

use super::attestation::{verify_statement, Context, Statement};
use super::cbor::Cbor;
use super::ceremony::Registration;
use crate::js;
use crate::Verdict;

/// The FIDO certification levels in order (MDS3 section 3.1.4.1).
pub const LEVELS: [&str; 7] =
    ["none", "L1", "L1plus", "L2", "L2plus", "L3", "L3plus"];

/// `PasskeyPolicy.isPostQuantum()`'s list (`POST_QUANTUM_ALGORITHMS`).
const POST_QUANTUM_ALGORITHMS: [&str; 3] =
    ["ML-DSA-87", "ML-DSA-65", "ML-DSA-44"];

/// The FIDO Metadata Service, as the verifier asks it.
pub trait Metadata: Send + Sync {
    /// `lookupAuthenticatorBy(kind, key)`: `{ model, version }`, or none.
    fn lookup_authenticator_by(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<Json>, String>;
}

/// Google's Android attestation status list, as the verifier asks it.
pub trait AndroidStatus: Send + Sync {
    /// `lookupAttestationSerials(serials)`: `{ checked, version, hits,
    /// why }`. `Err` is a list that could not be read.
    fn lookup_attestation_serials(
        &self,
        serials: &[String],
    ) -> Result<Json, String>;
}

/// `revocation_status.verdictFor()`, as the verifier asks it.
pub trait Revocation: Send + Sync {
    /// The verdict for an anchored chain (`{ leaf, chain, verified: true }`,
    /// `{ external: 'fetch' }`): `{ refused, status, unknown, why }`.
    fn verdict_for(
        &self,
        leaf_pem: &str,
        chain_pems: &[String],
    ) -> Result<Json, String>;
}

/// What the verifier reaches outside itself for (`WebauthnAttestationDeps`).
pub trait AttestationPorts: Send + Sync {
    /// `policy.attestationSettings()`.
    fn settings(&self) -> Json;
    /// `policy.insecureAlgorithmsAllowed()`.
    fn insecure_allowed(&self) -> bool;
    /// `deps.now()`.
    fn now_ms(&self) -> f64;
    /// The FIDO metadata (`deps.metadata()`).
    fn metadata(&self) -> &dyn Metadata;
    /// Revocation (`deps.revocation()`).
    fn revocation(&self) -> &dyn Revocation;
    /// Google's list (`deps.androidRevocation()`'s datasets).
    fn android_status(&self) -> &dyn AndroidStatus;
    /// `mode.refusesUncheckedAttestationRevocation()`.
    fn refuses_unchecked_android_revocation(&self) -> bool;
    /// The validation door in force for `webauthn-attestation` (#1360):
    /// `Some((ok, reason, chain))` where it applies, none for the baseline.
    fn paranoid_path(
        &self,
        _leaf: &[u8],
        _rest: &[Vec<u8>],
        _anchors: &[Entry],
        _tpm: bool,
    ) -> Option<(bool, String, Vec<Vec<u8>>)> {
        None
    }
    /// `CertificateTrust.anchorsAvailable()`'s signer-truststore half:
    /// whether the door holds anchors of its own for this purpose.
    fn truststore_anchors(&self) -> bool {
        false
    }
    /// `webauthn.attestationEvidenceTsaUrl`, trimmed.
    fn evidence_tsa_url(&self) -> String {
        String::new()
    }
    /// `passkey_evidence.create(archiveObject)` (#947).
    fn create_evidence(&self, _archive: &[u8]) -> Result<Json, String> {
        Err("no RFC 4998 evidence service is installed".to_string())
    }
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(other) => js::string(other),
    }
}

/// `WebauthnAttestation.aaguidString(value)`: a UUID, or empty for none
/// and the all-zero AAGUID.
#[tracing::instrument(level = "debug")]
pub fn aaguid_string(value: &str) -> String {
    let hex = value.to_lowercase().replace('-', "");
    if hex.len() != 32
        || !hex.chars().all(|c| c.is_ascii_hexdigit())
        || hex.chars().all(|c| c == '0')
    {
        return String::new();
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// `WebauthnPolicy.conveyanceFor(settings, listed)`.
#[tracing::instrument(level = "debug", skip(settings))]
pub fn conveyance_for(settings: &Json, listed: bool) -> Json {
    let configured = match settings.get("conveyance") {
        Some(v) if js::truthy(v) => js::string(v),
        _ => "direct".to_string(),
    };
    let downgraded = configured == "enterprise" && !listed;
    let requested = if configured == "enterprise" {
        if listed {
            "enterprise".to_string()
        } else {
            "direct".to_string()
        }
    } else if settings["demandsTrust"] == json!(true) {
        "direct".to_string()
    } else {
        configured.clone()
    };
    json!({ "configured": configured, "requested": requested,
            "downgraded": downgraded })
}

/// `WebauthnAttestation.flatAlgorithms(a)`.
fn flat_algorithms(a: &Json) -> (Vec<String>, Vec<Json>) {
    let mut parts = vec![a.clone()];
    if let Some(m) = a.get("members").and_then(Json::as_array) {
        parts.extend(m.iter().cloned());
    }
    let mut statements = Vec::new();
    let mut certificates = Vec::new();
    for one in &parts {
        if js::truthy_opt(one.get("statement")) {
            statements.push(text(one.get("statement")));
        }
        if let Some(c) = one.get("certificates").and_then(Json::as_array) {
            certificates.extend(c.iter().cloned());
        }
    }
    if js::truthy_opt(a.get("anchor")) {
        certificates.push(a["anchor"].clone());
    }
    (statements, certificates)
}

/// `WebauthnAttestation.postQuantumAttestation(a)`: a certificate at
/// least, and every statement and certificate signature post-quantum.
#[tracing::instrument(level = "debug", skip_all)]
pub fn post_quantum_attestation(a: &Json) -> bool {
    let (statements, certificates) = flat_algorithms(a);
    !certificates.is_empty()
        && statements
            .iter()
            .all(|s| POST_QUANTUM_ALGORITHMS.contains(&s.as_str()))
        && certificates.iter().all(|c| c["postQuantum"] == json!(true))
}

/// `WebauthnAttestation.recordedAlgorithms(rec)`: the facts the passkey
/// policy's `attestation-algorithm` group reads off a key's record.
#[tracing::instrument(level = "debug", skip_all)]
pub fn recorded_algorithms(rec: &Json) -> Json {
    let a = rec.get("algorithms").filter(|v| v.is_object());
    let (statements, certificates) = flat_algorithms(a.unwrap_or(&Json::Null));
    json!({
        "verified": rec.get("verified") == Some(&json!(true)),
        "trusted": rec.get("trusted") == Some(&json!(true)),
        "recorded": a.is_some(),
        "statement": a.map_or(String::new(), |a| text(a.get("statement"))),
        "statements": statements,
        "certificates": certificates.iter().map(|one| json!({
            "algorithm": text(one.get("algorithm")),
            "family": text(one.get("family")),
            "postQuantum": one.get("postQuantum") == Some(&json!(true)) }))
            .collect::<Vec<_>>(),
        "postQuantum": a.is_some_and(post_quantum_attestation),
    })
}

/// `heldLevel(m)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn held_level(m: &Json) -> String {
    let raw = text(m.get("certificationLevel"));
    let stripped = raw
        .strip_prefix("FIDO_CERTIFIED")
        .map(|r| r.strip_prefix('_').unwrap_or(r).to_string())
        .unwrap_or_else(|| raw.clone());
    if !stripped.is_empty() {
        stripped
    } else if !raw.is_empty() {
        "L1".to_string()
    } else {
        "none".to_string()
    }
}

/// `fipsCertified(m)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn fips_certified(m: &Json) -> bool {
    m["statusReports"].as_array().is_some_and(|l| {
        l.iter()
            .any(|r| text(r.get("status")).starts_with("FIPS140_CERTIFIED_L"))
    })
}

/// `compromisedStatuses(model)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn compromised_statuses(model: &Json) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for r in model["statusReports"].as_array().into_iter().flatten() {
        let s = text(r.get("status"));
        if super::metadata::MDS_COMPROMISED.contains(&s.as_str())
            && !seen.contains(&s)
        {
            seen.push(s);
        }
    }
    if seen.is_empty() {
        vec!["compromised".to_string()]
    } else {
        seen
    }
}

/// `demandedBy(settings)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn demanded_by(settings: &Json) -> String {
    let mut why = Vec::new();
    if settings["policy"] == json!("require-trusted") {
        why.push("webauthn.attestationPolicy is require-trusted".to_string());
    }
    if settings["allowedAaguids"]
        .as_array()
        .is_some_and(|l| !l.is_empty())
    {
        why.push("webauthn.attestationAllowedAaguids is set".to_string());
    }
    let level = text(settings.get("minCertificationLevel"));
    if level != "none" {
        why.push(format!(
            "webauthn.attestationMinCertificationLevel is {level}"
        ));
    }
    if settings["requireFips"] == json!(true) {
        why.push("webauthn.attestationRequireFips is on".to_string());
    }
    if js::truthy_opt(settings.get("enterpriseSerialAttribute")) {
        why.push(format!(
            "the passkey policy binds security-key serials ({})",
            text(settings.get("enterpriseSerialAttribute"))
        ));
    }
    if let Some(list) = settings["attestationAlgorithms"]
        .as_array()
        .filter(|l| !l.is_empty())
    {
        let names: Vec<String> = list.iter().map(js::string).collect();
        why.push(format!(
            "the passkey policy requires an attestation signed with {} \
             (attestationAlgorithms)",
            names.join(", ")
        ));
    }
    why.join("; ")
}

/// `levelProblem(listed, settings)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn level_problem(listed: Option<&Json>, settings: &Json) -> String {
    let min = text(settings.get("minCertificationLevel"));
    let want_level = min != "none";
    let fips = settings["requireFips"] == json!(true);
    if !want_level && !fips {
        return String::new();
    }
    let Some(listed) = listed else {
        return format!(
            "The FIDO Metadata Service does not list this authenticator \
             model, so its certification cannot be known, and this realm \
             requires {}.",
            demanded_by(settings)
        );
    };
    let m = listed.get("model").cloned().unwrap_or(json!({}));
    if want_level {
        let held = held_level(&m);
        let rank = |l: &str| {
            LEVELS.iter().position(|x| *x == l).map_or(-1, |p| p as i64)
        };
        if rank(&held) < rank(&min) {
            return format!(
                "This authenticator model is certified at {held} and this \
                 realm requires at least {min} \
                 (webauthn.attestationMinCertificationLevel)."
            );
        }
    }
    if fips && !fips_certified(&m) {
        return "The FIDO Metadata Service reports no FIPS 140 certification \
                for this authenticator model, and this realm requires one \
                (webauthn.attestationRequireFips)."
            .to_string();
    }
    String::new()
}

/// `mdsRoots(listed)`: the attestation roots MDS lists for the model.
fn mds_roots(listed: Option<&Json>) -> Vec<Entry> {
    listed
        .and_then(|l| {
            l["model"]["metadataStatement"]["attestationRootCertificates"]
                .as_array()
        })
        .into_iter()
        .flatten()
        .filter_map(|b64| {
            Entry::from_der(&sts_pki::foreign::node_base64(&js::string(b64)))
        })
        .collect()
}

/// `leafOf(statement)`: the first certificate, or a compound's first
/// member's that carries one.
fn leaf_of(statement: &Statement) -> Option<Vec<u8>> {
    let Statement::Verified {
        trust_path, subs, ..
    } = statement
    else {
        return None;
    };
    if let Some(first) = trust_path.first() {
        return Some(first.clone());
    }
    subs.iter().find_map(|s| match s {
        Statement::Verified { trust_path, .. } => trust_path.first().cloned(),
        Statement::Refused { .. } => None,
    })
}

/// `trustOf()`'s answer.
#[derive(Debug, Clone, Default)]
struct Trust {
    trusted: bool,
    anchor: String,
    why: String,
    refusal: Option<(ErrorCode, String)>,
    anchor_der: Option<Vec<u8>>,
    android: Option<Json>,
}

/// One attestation verifier over its ports.
pub struct Attestation<'a> {
    ports: &'a dyn AttestationPorts,
}

impl<'a> Attestation<'a> {
    /// Built over the ports.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(ports: &'a dyn AttestationPorts) -> Attestation<'a> {
        Attestation { ports }
    }

    /// The statement procedures' context for a registration, under
    /// `settings`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn context(&self, r: &Registration, settings: &Json) -> Context {
        Context {
            auth_data: r.auth_data.clone(),
            client_data_hash: r.client_data_hash.clone(),
            cose: r.credential_public_key.clone(),
            cose_alg: r.cose_alg,
            credential_jwk: r.answer["publicKeyJwk"].clone(),
            aaguid: r.aaguid.clone(),
            credential_id: r.credential_id.clone(),
            rp_id_hash: r.rp_id_hash.clone(),
            allow_insecure: self.ports.insecure_allowed(),
            android_software_keys: settings["androidSoftwareKeys"]
                == json!(true),
            now_ms: self.ports.now_ms(),
        }
    }

    /// `assess(verdict)`: `{ ok: true, attestation }`, or `{ ok: false,
    /// why, attestation }` with its code.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn assess(&self, r: &Registration) -> Verdict {
        let settings = self.ports.settings();
        let format = text(r.answer.get("fmt"));
        let mut base = Map::new();
        base.insert("policy".into(), settings["policy"].clone());
        base.insert("format".into(), json!(format));
        base.insert("type".into(), json!("unverified"));
        base.insert("verified".into(), json!(false));
        base.insert("trusted".into(), json!(false));
        base.insert("anchor".into(), json!(""));
        base.insert(
            "aaguid".into(),
            json!(aaguid_string(&text(r.answer.get("aaguid")))),
        );
        for k in ["model", "certificationLevel", "mdsStatus", "mdsVersion"] {
            base.insert(k.into(), json!(""));
        }
        base.insert("checkedAt".into(), js::num(self.ports.now_ms()));
        base.insert(
            "algorithms".into(),
            self.algorithms_of(&format, r.att_stmt.as_ref(), None),
        );
        let hash = &r.rp_id_hash;
        let listed = settings["enterpriseRpIds"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|rp| {
                hash.len() == 32
                    && Hash::Sha256.digest(js::string(rp).as_bytes()) == *hash
            });
        let asked = conveyance_for(&settings, listed);
        base.insert("conveyance".into(), asked["requested"].clone());
        base.insert("enterpriseDowngraded".into(), asked["downgraded"].clone());
        if settings["policy"] == json!("off")
            && settings["demandsTrust"] != json!(true)
        {
            return Verdict::of(json!({ "ok": true,
                                       "attestation": Json::Object(base) }));
        }
        match self.assess_under(r, &settings, &base, &format) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "{}webauthn: verifying a {} attestation statement \
                     threw: {}",
                    sts_core::log::tag(codes::STS_AUTHN_0241),
                    format,
                    e
                );
                Verdict::coded(
                    codes::STS_AUTHN_0241,
                    json!({ "ok": false, "attestation": Json::Object(base),
                        "why": format!("The authenticator's attestation \
                            statement could not be checked: {e}") }),
                )
            }
        }
    }

    fn refuse(
        code: ErrorCode,
        why: String,
        record: &Map<String, Json>,
    ) -> Verdict {
        Verdict::coded(
            code,
            json!({ "ok": false, "why": why,
                    "attestation": Json::Object(record.clone()) }),
        )
    }

    fn assess_under(
        &self,
        r: &Registration,
        settings: &Json,
        base: &Map<String, Json>,
        format: &str,
    ) -> Result<Verdict, String> {
        let ctx = self.context(r, settings);
        let st = r.att_stmt.clone().unwrap_or(Cbor::Null);
        let statement = verify_statement(format, &st, &ctx);
        let (kind, acki) = match &statement {
            Statement::Refused { code, why, .. } => {
                tracing::info!(
                    "webauthn: a {format} attestation statement was REFUSED: \
                     {why}"
                );
                return Ok(Attestation::refuse(
                    *code,
                    format!(
                        "The authenticator's attestation statement does not \
                         verify: {why}."
                    ),
                    base,
                ));
            }
            Statement::Verified { kind, acki, .. } => (*kind, acki.clone()),
        };
        let mut rec = base.clone();
        rec.insert("verified".into(), json!(true));
        rec.insert("type".into(), json!(kind));
        let key_leaf = leaf_of(&statement);
        let key_id =
            acki.clone().filter(|a| !a.is_empty()).unwrap_or_else(|| {
                key_leaf
                    .as_deref()
                    .map_or(String::new(), attestation_key_identifier)
            });
        rec.insert("attestationKeyId".into(), json!(key_id));
        if base["conveyance"] == json!("enterprise") {
            if let Some(serial) =
                key_leaf.as_deref().and_then(attestation_device_serial)
            {
                rec.insert("deviceSerial".into(), serial["serial"].clone());
                rec.insert(
                    "deviceSerialSource".into(),
                    serial["source"].clone(),
                );
            }
        }
        let aaguid = text(base.get("aaguid"));
        let listed = self.model_of(&statement, &aaguid, &key_leaf)?;
        if let Some(l) = &listed {
            let m = l.get("model").cloned().unwrap_or(json!({}));
            rec.insert("model".into(), json!(text(m.get("description"))));
            rec.insert(
                "certificationLevel".into(),
                json!(text(m.get("certificationLevel"))),
            );
            rec.insert("mdsStatus".into(), json!(text(m.get("latestStatus"))));
            rec.insert("mdsVersion".into(), json!(text(l.get("version"))));
            if js::truthy_opt(m.get("compromised")) {
                let model = text(rec.get("model"));
                let named = if !model.is_empty() {
                    model
                } else if !aaguid.is_empty() {
                    aaguid.clone()
                } else {
                    "unnamed".to_string()
                };
                return Ok(Attestation::refuse(
                    codes::STS_AUTHN_0237,
                    format!(
                        "The FIDO Metadata Service reports this \
                         authenticator model ({named}) as {}, so a key from \
                         it is not registered here.",
                        compromised_statuses(&m).join(", ")
                    ),
                    &rec,
                ));
            }
        }
        let trust = self.trust_of(&statement, listed.as_ref(), settings)?;
        if let Some((code, why)) = trust.refusal {
            tracing::info!(
                "webauthn: a {format} attestation was REFUSED: {why}"
            );
            return Ok(Attestation::refuse(code, why, &rec));
        }
        rec.insert("trusted".into(), json!(trust.trusted));
        rec.insert("anchor".into(), json!(trust.anchor));
        if trust.trusted {
            if let Some(der) = &trust.anchor_der {
                rec.insert(
                    "algorithms".into(),
                    self.algorithms_of(format, r.att_stmt.as_ref(), Some(der)),
                );
            }
        }
        if let Some(android) = &trust.android {
            rec.insert("androidRevocation".into(), android.clone());
        }
        if settings["demandsTrust"] == json!(true) && !trust.trusted {
            let self_or_none = kind == "none" || kind == "self";
            let first = if self_or_none {
                format!(
                    "The authenticator sent {}, which proves nothing about \
                     what made the key",
                    if kind == "none" {
                        "no attestation"
                    } else {
                        "a self attestation"
                    }
                )
            } else {
                format!(
                    "The attestation does not chain to a trust anchor this \
                     realm or the FIDO Metadata Service holds{}",
                    if trust.why.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", trust.why)
                    }
                )
            };
            return Ok(Attestation::refuse(
                if self_or_none {
                    codes::STS_AUTHN_0240
                } else {
                    codes::STS_AUTHN_0235
                },
                format!(
                    "{first}, and this realm requires a trusted one ({}).",
                    demanded_by(settings)
                ),
                &rec,
            ));
        }
        let allowed: Vec<String> = settings["allowedAaguids"]
            .as_array()
            .into_iter()
            .flatten()
            .map(js::string)
            .collect();
        if !allowed.is_empty() && !allowed.contains(&aaguid.replace('-', "")) {
            return Ok(Attestation::refuse(
                codes::STS_AUTHN_0236,
                format!(
                    "This authenticator model (AAGUID {}) is not one this \
                     realm allows (webauthn.attestationAllowedAaguids).",
                    if aaguid.is_empty() { "none" } else { &aaguid }
                ),
                &rec,
            ));
        }
        let problem = level_problem(listed.as_ref(), settings);
        if !problem.is_empty() {
            return Ok(Attestation::refuse(
                codes::STS_AUTHN_0238,
                problem,
                &rec,
            ));
        }
        if rec["trusted"] == json!(true)
            && rec["verified"] == json!(true)
            && !post_quantum_attestation(&rec["algorithms"])
            && !self.ports.evidence_tsa_url().is_empty()
        {
            let evidence = self.evidence(r, &rec)?;
            rec.insert("evidence".into(), evidence);
        }
        tracing::info!(
            "webauthn: a {format} attestation verified ({kind}, {}).",
            if trust.trusted {
                format!("trusted through {}", text(rec.get("anchor")))
            } else {
                "untrusted".to_string()
            }
        );
        Ok(Verdict::of(json!({ "ok": true,
                               "attestation": Json::Object(rec) })))
    }

    /// RFC 4998 evidence of an accepted classical attestation (#947): the
    /// raw attestation object and the result this service accepted, framed
    /// as Node frames them.
    fn evidence(
        &self,
        r: &Registration,
        rec: &Map<String, Json>,
    ) -> Result<Json, String> {
        let raw = &r.attestation_object;
        if raw.is_empty() {
            return Err(
                "The raw attestation object was not preserved.".to_string()
            );
        }
        let result = json!({ "fmt": rec["format"], "type": rec["type"],
            "verified": rec["verified"], "trusted": rec["trusted"],
            "anchor": rec["anchor"], "aaguid": rec["aaguid"],
            "algorithms": rec["algorithms"] })
        .to_string();
        let mut archive = b"IYA-PASSKEY-ATTESTATION-EVIDENCE-1\0".to_vec();
        archive.extend((raw.len() as u32).to_be_bytes());
        archive.extend((result.len() as u32).to_be_bytes());
        archive.extend(raw);
        archive.extend(result.as_bytes());
        self.ports.create_evidence(&archive)
    }

    /// `modelOf(statement, aaguid)`: by AAGUID, then by the attestation
    /// key identifier.
    fn model_of(
        &self,
        statement: &Statement,
        aaguid: &str,
        leaf: &Option<Vec<u8>>,
    ) -> Result<Option<Json>, String> {
        let metadata = self.ports.metadata();
        if !aaguid.is_empty() {
            if let Some(hit) =
                metadata.lookup_authenticator_by("aaguid", aaguid)?
            {
                return Ok(Some(hit));
            }
        }
        let acki = match statement {
            Statement::Verified { acki: Some(a), .. } if !a.is_empty() => {
                a.clone()
            }
            _ => leaf
                .as_deref()
                .map_or(String::new(), attestation_key_identifier),
        };
        if acki.is_empty() {
            return Ok(None);
        }
        metadata.lookup_authenticator_by("acki", &acki)
    }

    /// `trustOf(statement, listed, settings)`.
    fn trust_of(
        &self,
        statement: &Statement,
        listed: Option<&Json>,
        settings: &Json,
    ) -> Result<Trust, String> {
        let Statement::Verified {
            format,
            kind,
            trust_path,
            safetynet,
            subs,
            ..
        } = statement
        else {
            return Ok(Trust::default());
        };
        if *kind == "compound" {
            let mut trusted: Option<Trust> = None;
            for sub in subs {
                let one = self.trust_of(sub, listed, settings)?;
                if one.refusal.is_some() {
                    return Ok(one);
                }
                if one.trusted && trusted.is_none() {
                    trusted = Some(one);
                }
            }
            return Ok(trusted.unwrap_or(Trust {
                why: "no member chains to an anchor".to_string(),
                ..Trust::default()
            }));
        }
        if trust_path.is_empty() {
            return Ok(Trust {
                why: (*kind).to_string(),
                ..Trust::default()
            });
        }
        let (mut anchors, _) =
            certificate_bundle(&text(settings.get("trustAnchorsPem")));
        let from_mds = mds_roots(listed);
        let mds_ders: Vec<Vec<u8>> =
            from_mds.iter().map(|e| e.der.clone()).collect();
        anchors.extend(from_mds);
        let leaf = &trust_path[0];
        let rest = &trust_path[1..];
        let tpm = format == "tpm";
        let (ok, reason, chain) =
            if anchors.is_empty() && !self.ports.truststore_anchors() {
                (
                    false,
                    "no trust anchor is configured or listed".to_string(),
                    Vec::new(),
                )
            } else if let Some(door) =
                self.ports.paranoid_path(leaf, rest, &anchors, tpm)
            {
                door
            } else {
                let v = verify_path_to_anchors(
                    leaf,
                    rest,
                    &anchors,
                    &PathOptions {
                        now_ms: self.ports.now_ms() as i64,
                        ..PathOptions::default()
                    },
                );
                (v.ok, v.reason, v.chain)
            };
        if !ok {
            if !mds_ders.is_empty() {
                return Ok(Trust {
                    why: reason.clone(),
                    refusal: Some((
                        codes::STS_AUTHN_0235,
                        format!(
                            "The FIDO Metadata Service lists this \
                             authenticator model, and its attestation does \
                             not chain to the roots MDS lists for it: \
                             {reason}."
                        ),
                    )),
                    ..Trust::default()
                });
            }
            return Ok(Trust {
                why: reason,
                ..Trust::default()
            });
        }
        let top = chain.last().cloned().unwrap_or_default();
        let anchor = if mds_ders.contains(&top) {
            "mds"
        } else {
            "configured"
        };
        if let Some((code, why)) = self.revocation_of(&chain)? {
            return Ok(Trust {
                why: why.clone(),
                refusal: Some((code, why)),
                ..Trust::default()
            });
        }
        if *safetynet && settings["allowSafetynet"] != json!(true) {
            return Ok(Trust {
                why: "android-safetynet is not trusted here \
                      (webauthn.attestationAllowSafetynet)"
                    .to_string(),
                ..Trust::default()
            });
        }
        let mut android = None;
        if format == "android-key" {
            let verdict = self.android_consult(&chain);
            if self.android_untrusts(&verdict) {
                tracing::info!(
                    "{}webauthn: an android-key attestation chained to an \
                     anchor and is NOT trusted: {}.",
                    sts_core::log::tag(codes::STS_AUTHN_0297),
                    android_describe(&verdict)
                );
                return Ok(Trust {
                    why: android_describe(&verdict),
                    android: Some(verdict),
                    ..Trust::default()
                });
            }
            android = Some(verdict);
        }
        Ok(Trust {
            trusted: true,
            anchor: anchor.to_string(),
            why: String::new(),
            refusal: None,
            anchor_der: Some(top),
            android,
        })
    }

    /// `revocationOf(chain)`: none, or the refusal — a certificate that
    /// names no distribution point not refused for it.
    fn revocation_of(
        &self,
        chain: &[Vec<u8>],
    ) -> Result<Option<(ErrorCode, String)>, String> {
        let pems: Vec<String> = chain
            .iter()
            .filter_map(|d| Entry::from_der(d).map(|e| e.pem))
            .collect();
        let Some((leaf, rest)) = pems.split_first() else {
            return Ok(None);
        };
        let verdict = self.ports.revocation().verdict_for(leaf, rest)?;
        if verdict.is_null() || !js::truthy_opt(verdict.get("refused")) {
            return Ok(None);
        }
        let unknown: Vec<&Json> = verdict["unknown"]
            .as_array()
            .map(|l| l.iter().collect())
            .unwrap_or_default();
        let only_unpublished = verdict["status"] == json!("unknown")
            && unknown
                .iter()
                .filter(|o| {
                    js::truthy_opt(o.get("refusable"))
                        || js::truthy_opt(o.get("invalid"))
                })
                .all(|o| {
                    o["kind"] == json!("no-distribution-point")
                        && !js::truthy_opt(o.get("invalid"))
                });
        if only_unpublished {
            return Ok(None);
        }
        Ok(Some((
            codes::STS_AUTHN_0239,
            format!(
                "A certificate in the attestation chain is {}: {}",
                if verdict["status"] == json!("revoked") {
                    "REVOKED"
                } else {
                    "of a revocation status that could not be established"
                },
                text(verdict.get("why"))
            ),
        )))
    }

    /// `AttestationRevocation.consult(chain)`: what Google's list says of
    /// every certificate of an Android chain.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn android_consult(&self, chain: &[Vec<u8>]) -> Json {
        let serials: Vec<String> = chain
            .iter()
            .take(8)
            .map(|d| certificate_serial_hex(d))
            .filter(|s| !s.is_empty())
            .collect();
        let checked_at = sts_pki::foreign::iso_ms(self.ports.now_ms() as i64);
        let lookup = match self
            .ports
            .android_status()
            .lookup_attestation_serials(&serials)
        {
            Ok(l) => l,
            Err(e) => json!({ "checked": false, "version": "", "hits": [],
                "why": format!("the Android attestation status list could \
                                not be read: {e}") }),
        };
        if lookup["checked"] != json!(true) {
            let why = match lookup.get("why") {
                Some(w) if js::truthy(w) => js::string(w),
                _ => "no list".to_string(),
            };
            return json!({ "status": "unchecked", "reason": "", "serial": "",
                "listVersion": text(lookup.get("version")),
                "checkedAt": checked_at, "chainSerials": serials,
                "why": why });
        }
        let hits: Vec<&Json> = lookup["hits"]
            .as_array()
            .map(|l| l.iter().collect())
            .unwrap_or_default();
        let hit = hits
            .iter()
            .find(|h| h["status"] == json!("REVOKED"))
            .or_else(|| {
                hits.iter().find(|h| h["status"] == json!("SUSPENDED"))
            });
        json!({
            "status": hit.map_or("good".to_string(),
                                 |h| text(h.get("status")).to_lowercase()),
            "reason": hit.map_or(String::new(), |h| text(h.get("reason"))),
            "serial": hit.map_or(String::new(), |h| text(h.get("serial"))),
            "listVersion": text(lookup.get("version")),
            "checkedAt": checked_at, "chainSerials": serials, "why": ""
        })
    }

    /// `AttestationRevocation.untrusts(verdict)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn android_untrusts(&self, verdict: &Json) -> bool {
        let status = match verdict.get("status") {
            Some(s) if js::truthy(s) => js::string(s),
            _ => "unchecked".to_string(),
        };
        status == "revoked"
            || status == "suspended"
            || (status == "unchecked"
                && self.ports.refuses_unchecked_android_revocation())
    }

    /// `algorithmsOf(format, attStmt, anchorDer)` (#941).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn algorithms_of(
        &self,
        format: &str,
        st: Option<&Cbor>,
        anchor: Option<&[u8]>,
    ) -> Json {
        let mut out = Map::new();
        out.insert("statement".into(), json!(""));
        out.insert("statementCoseAlg".into(), Json::Null);
        out.insert("certificates".into(), json!([]));
        out.insert("anchor".into(), Json::Null);
        out.insert("members".into(), json!([]));
        out.insert("postQuantum".into(), json!(false));
        match (format, st) {
            ("compound", Some(Cbor::Array(items))) => {
                let members: Vec<Json> = items
                    .iter()
                    .take(4)
                    .map(|one| {
                        let fmt = match one.get_text("fmt") {
                            Some(Cbor::Text(t)) if !t.is_empty() => t.clone(),
                            _ => String::new(),
                        };
                        let mut m = Map::new();
                        m.insert("format".into(), json!(fmt));
                        for (k, v) in
                            member_algorithms(&fmt, one.get_text("attStmt"))
                        {
                            m.insert(k, v);
                        }
                        Json::Object(m)
                    })
                    .collect();
                out.insert("members".into(), Json::Array(members));
            }
            _ => {
                for (k, v) in member_algorithms(format, st) {
                    out.insert(k, v);
                }
            }
        }
        out.insert(
            "anchor".into(),
            anchor
                .and_then(attestation_signature_algorithm)
                .unwrap_or(Json::Null),
        );
        let pq = post_quantum_attestation(&Json::Object(out.clone()));
        out.insert("postQuantum".into(), json!(pq));
        Json::Object(out)
    }
}

/// `AttestationRevocation.describe(verdict)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn android_describe(v: &Json) -> String {
    let version = text(v.get("listVersion"));
    let list = format!(
        "Google's Android attestation status list{}",
        if version.is_empty() {
            String::new()
        } else {
            format!(" {version}")
        }
    );
    let status = text(v.get("status"));
    if status == "good" {
        format!("no certificate of the chain is revoked ({list})")
    } else if status == "revoked" || status == "suspended" {
        let reason = text(v.get("reason"));
        format!(
            "certificate {} of the chain is {}{} in {list}",
            text(v.get("serial")),
            status.to_uppercase(),
            if reason.is_empty() {
                String::new()
            } else {
                format!(" ({reason})")
            }
        )
    } else {
        let why = match v.get("why") {
            Some(w) if js::truthy(w) => js::string(w),
            _ => "no list".to_string(),
        };
        format!("its revocation is UNCHECKED: {why}")
    }
}

/// `memberAlgorithms(format, st)`: one statement's algorithm and chain.
fn member_algorithms(format: &str, st: Option<&Cbor>) -> Vec<(String, Json)> {
    let map = st.filter(|s| matches!(s, Cbor::Map(_)));
    let ders = |v: Option<&Cbor>| -> Vec<Vec<u8>> {
        match v {
            Some(Cbor::Array(items)) => items
                .iter()
                .filter_map(|i| i.bytes().map(<[u8]>::to_vec))
                .collect(),
            _ => Vec::new(),
        }
    };
    let get = |k: &str| map.and_then(|m| m.get_text(k));
    let mut cose: Option<i64> = None;
    let mut named = String::new();
    let mut chain: Vec<Vec<u8>> = Vec::new();
    match format {
        "packed" | "tpm" | "android-key" => {
            cose = get("alg").and_then(Cbor::int);
            chain = ders(get("x5c"));
        }
        "fido-u2f" => {
            cose = Some(-7);
            chain = ders(get("x5c"));
        }
        "apple" => chain = ders(get("x5c")),
        "android-safetynet" => {
            if let Some(response) = get("response")
                .filter(|r| !matches!(r, Cbor::Null | Cbor::Bool(false)))
            {
                let jws = match response {
                    Cbor::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                    other => other.text_of(),
                };
                let header: Option<Json> =
                    serde_json::from_slice(&super::ceremony::from_base64url(
                        jws.split('.').next().unwrap_or(""),
                    ))
                    .ok();
                if let Some(h) = &header {
                    if let Some(a) = h.get("alg").and_then(Json::as_str) {
                        named = a.chars().take(20).collect();
                    }
                    chain = h["x5c"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .take(8)
                        .map(|one| {
                            sts_pki::foreign::node_base64(&js::string(one))
                        })
                        .collect();
                }
            }
        }
        _ => {}
    }
    if let Some(id) = cose {
        named = cose_signature_alg(id)
            .map_or(format!("COSE {id}"), |s| s.name.to_string());
    }
    let certificates: Vec<Json> = chain
        .iter()
        .take(8)
        .map(|der| {
            attestation_signature_algorithm(der).unwrap_or(json!({
                "algorithm": "unreadable", "oid": "", "family": "unknown",
                "postQuantum": false, "composite": false }))
        })
        .collect();
    vec![
        ("statement".to_string(), json!(named)),
        (
            "statementCoseAlg".to_string(),
            cose.map_or(Json::Null, |c| json!(c)),
        ),
        ("certificates".to_string(), Json::Array(certificates)),
    ]
}
