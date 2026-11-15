// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `common/pki.js`'s hierarchy: building the Root (`buildRootNow()`,
//! `ensureRoot()`, `buildRoot()` — the operation `POST
//! /admin-api/pki/build-root` performs), a scope's branch
//! (`buildScopeNow()`, `ensureScope()`, `topUpScopeNow()`,
//! `repairBranch()`), every tier made by `issueCaTier()`, and the reads the
//! rest of the service makes of it (`serviceRoot()`, `rawRowFor()`,
//! `scopeChainsToRoot()`, `chainPemFor()`, `trustAnchorsFor()`,
//! `chainThroughRoot()`, `describeIssuer()`).
//!
//! **What replaced what.** Node serialises builds of one scope with a
//! promise chain (`oneBuildAtATime()`) and, where the store arbitrates,
//! claims the build across nodes (`oneBuildInTheCluster()`); here a build
//! holds [`Authority`]'s build lock for its whole length, and the row is
//! read again under it, so a build another caller finished first is
//! adopted rather than repeated. Across nodes the store's merge
//! ([`super::merge`]) is what keeps a tier first-writer-wins — the claim
//! that saves the redundant key generation is not ported (it is an
//! optimisation, not a correctness rule: the merge discards the loser's
//! tier and says so).
//!
//! Every certificate is written by [`crate::x509::issue`], which is
//! `x509.js` byte for byte, so a tier built here is a tier Node would have
//! built from the same key; the row records it in Node's member order.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use chrono::{DateTime, Datelike, Duration, Utc};
use openssl::sha::sha256;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;

use super::catalog::{
    self, key_alg, scope_id, scope_kind_of, use_case, use_cases_for, ScopeKind,
    UseCase, DEFAULT_KEY_ALG, DEFAULT_ORGANISATION, DEFAULT_SIG_ALG,
    PROCESS_SCOPE, SERVICE_SCOPE,
};
use super::config::PkiConfig;
use super::rows::RowStore;
use crate::der;
use crate::x509::algorithms;
use crate::x509::extensions as ext;
use crate::x509::issue::issue_certificate;
use crate::x509::keys::{der_to_pem, pem_to_der};
use crate::x509::read::{verify_signature, Certificate};
use crate::x509::time;

/// A refusal: Node's `{ ok: false, errors }`, with the code it was marked
/// with (recorded, never sent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: ErrorCode,
    pub errors: Vec<String>,
}

impl Refusal {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(code: ErrorCode, sentence: impl Into<String>) -> Refusal {
        Refusal {
            code,
            errors: vec![sentence.into()],
        }
    }

    /// The errors as one line, as a page joins them.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sentence(&self) -> String {
        self.errors.join(" ")
    }
}

/// What a build may be asked for (`buildRoot(opts)`, `buildScope(opts)`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildOptions {
    pub key_alg: Option<String>,
    pub signature_alg: Option<String>,
    pub alt_key_alg: Option<String>,
    pub organisation: Option<String>,
    pub country: Option<String>,
    /// The Root's common name (`commonName`).
    pub common_name: Option<String>,
    /// `commonNames.intermediate`.
    pub intermediate_cn: Option<String>,
    /// `years`: per tier.
    pub root_years: Option<i64>,
    pub intermediate_years: Option<i64>,
    pub issuing_years: Option<i64>,
    pub replace_imported: bool,
}

impl BuildOptions {
    /// The options as the console and the API send them.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(v: &Json) -> BuildOptions {
        let text = |k: &str| {
            v.get(k)
                .and_then(Json::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let years = v.get("years");
        let year = |tier: &str| -> Option<i64> {
            let asked = match years {
                Some(Json::Object(m)) => m.get(tier).cloned(),
                Some(n) if tier == "root" => Some(n.clone()),
                _ => None,
            }?;
            let n = asked
                .as_f64()
                .or_else(|| asked.as_str().and_then(|s| s.parse().ok()))?;
            (n.is_finite() && n > 0.0).then_some(n.floor() as i64)
        };
        BuildOptions {
            key_alg: text("keyAlg"),
            signature_alg: text("signatureAlg"),
            alt_key_alg: text("altKeyAlg"),
            organisation: text("organisation"),
            country: v
                .get("country")
                .and_then(Json::as_str)
                .map(str::to_string),
            common_name: text("commonName"),
            intermediate_cn: v
                .get("commonNames")
                .and_then(|c| c.get("intermediate"))
                .and_then(Json::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            root_years: year("root"),
            intermediate_years: year("intermediate"),
            issuing_years: year("issuing"),
            replace_imported: v
                .get("replaceImported")
                .and_then(Json::as_bool)
                .unwrap_or(false),
        }
    }
}

/// `algorithmsFrom()`'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    pub key_alg: String,
    pub signature_alg: String,
    pub alt_key_alg: Option<String>,
}

/// What `issueCaTier()` is asked to make.
#[derive(Debug, Clone)]
struct CaSpec {
    tier: &'static str,
    profile: &'static str,
    label: String,
    use_case: Option<&'static str>,
    scope: String,
    cn: String,
    organisation: String,
    country: String,
    key_alg: String,
    signature_alg: String,
    /// `undefined` (None) is the setting's; `Some(None)` is classical.
    alt_key_alg: Option<Option<String>>,
    path_len: Option<i64>,
    years: i64,
    parent: Option<Json>,
}

/// What `issueUnder()` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    pub subject: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_alg: String,
    /// The leaf, then its Issuing CA and Intermediate.
    pub chain_pem: Vec<String>,
    /// The Issuing CA and Intermediate.
    pub issuer_chain_pem: Vec<String>,
}

/// `issueUnder()`'s spec.
#[derive(Debug, Clone, Default)]
pub struct LeafSpec {
    /// A DN string or `[{ name, value }]`.
    pub subject: Json,
    pub public_key_pem: String,
    pub profile: Option<String>,
    /// Milliseconds; `None` is now.
    pub not_before_ms: Option<i64>,
    pub not_after_ms: i64,
    pub extensions: Option<Json>,
}

/// `issueEnrolled()`'s spec (`cert_enrollment.ts`'s call).
#[derive(Debug, Clone, Default)]
pub struct EnrolledSpec {
    pub subject: Json,
    pub public_key_pem: String,
    pub profile: String,
    pub days: i64,
    /// `[{ kind, value }]`.
    pub subject_alt_name: Vec<Json>,
    pub identifier: String,
    pub subject_kind: String,
    pub holder_subject: String,
}

/// `certify()`'s spec: a certificate over one of this service's own keys,
/// recorded in the row's `certs` under `<useCase>:<slot>`.
#[derive(Debug, Clone, Default)]
pub struct CertifySpec {
    pub slot: String,
    pub label: Option<String>,
    pub common_name: Option<String>,
    pub public_key_pem: String,
    pub alt_public_key_pem: Option<String>,
    pub alg: String,
    pub key_alg: String,
    pub kid: Option<String>,
    pub generation_slot: bool,
    pub days: Option<i64>,
    pub profile: Option<String>,
    pub key_usage: Option<Vec<String>>,
    pub extensions: Option<Json>,
    pub holder_subject: Option<String>,
}

/// The certificate authority: the rows, the settings it reads, and the
/// build lock.
pub struct Authority {
    rows: Arc<dyn RowStore>,
    config: RwLock<PkiConfig>,
    builds: Mutex<()>,
    /// `lastCrlNumbers`: the highest CRL number this process signed, per
    /// authority.
    pub(super) crl_numbers: Mutex<BTreeMap<String, i64>>,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authority").finish()
    }
}

/// `certificateInstant()`: now (or a moment) at whole seconds.
#[tracing::instrument(level = "debug")]
pub fn certificate_instant(at_ms: Option<i64>) -> DateTime<Utc> {
    let ms = at_ms.unwrap_or_else(|| Utc::now().timestamp_millis());
    DateTime::from_timestamp_millis(ms - ms.rem_euclid(1000))
        .unwrap_or_else(Utc::now)
}

/// `Date.prototype.setUTCFullYear(year + n)`.
fn add_years(t: DateTime<Utc>, years: i64) -> Option<DateTime<Utc>> {
    let year = i32::try_from(i64::from(t.year()) + years).ok()?;
    t.with_year(year).or_else(|| {
        t.with_day(1)
            .and_then(|d| d.with_month(3))
            .and_then(|d| d.with_year(year))
    })
}

/// `thumbprintOf()`: SHA-256 of the DER, hex. A PEM that is not a
/// certificate (a public key) is read as the base64 between its lines.
#[tracing::instrument(level = "debug", skip_all)]
pub fn thumbprint_of(pem: &str) -> String {
    let der = pem_to_der(pem).unwrap_or_default();
    der::hex(&sha256(&der))
}

/// The milliseconds of an ISO time a row holds.
#[tracing::instrument(level = "debug")]
pub fn ms_of(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc).timestamp_millis())
}

fn str_of<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

impl Authority {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(rows: Arc<dyn RowStore>, config: PkiConfig) -> Arc<Authority> {
        Arc::new(Authority {
            rows,
            config: RwLock::new(config),
            builds: Mutex::new(()),
            crl_numbers: Mutex::new(BTreeMap::new()),
        })
    }

    /// The settings as they are now.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn config(&self) -> PkiConfig {
        self.config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The settings changed (an override, a realm added).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_config(&self, config: PkiConfig) {
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = config;
    }

    /// Whether the hierarchy outlives the process.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn persists(&self) -> bool {
        self.rows.persists()
    }

    fn lock_builds(&self) -> MutexGuard<'_, ()> {
        self.builds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // -----------------------------------------------------------------
    // The rows.
    // -----------------------------------------------------------------

    /// `rawRowFor()`: a scope's whole row, private keys included.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn raw_row_for(&self, scope: &str) -> Option<Json> {
        self.rows.get(&scope_id(scope))
    }

    /// `serviceRoot()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn service_root(&self) -> Option<Json> {
        self.rows
            .get(SERVICE_SCOPE)
            .and_then(|row| row.get("root").cloned())
            .filter(|r| !r.is_null())
    }

    /// `hasRoot()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn has_root(&self) -> bool {
        self.service_root().is_some()
    }

    /// `knownScopes()`: every scope holding a row but the service's.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn known_scopes(&self) -> Vec<String> {
        self.rows
            .scopes()
            .into_iter()
            .filter(|s| s != SERVICE_SCOPE)
            .collect()
    }

    /// `saveRow()`: writes a scope's row back, or removes it when nothing
    /// is left in it — no tier, no object, no revocation.
    #[tracing::instrument(level = "debug", skip(self, row))]
    pub fn save_row(&self, scope: &str, row: &Json) {
        let id = scope_id(scope);
        let nonempty = |k: &str| {
            row.get(k)
                .and_then(Json::as_array)
                .is_some_and(|a| !a.is_empty())
        };
        let lists =
            row.get("revoked")
                .and_then(Json::as_object)
                .is_some_and(|m| {
                    m.values()
                        .any(|l| l.as_array().is_some_and(|a| !a.is_empty()))
                });
        let held = |k: &str| row.get(k).is_some_and(|v| !v.is_null());
        if !nonempty("tiers")
            && !nonempty("objects")
            && !held("intermediate")
            && !held("root")
            && !lists
        {
            self.rows.attach(&id, None);
            return;
        }
        self.rows.attach(&id, Some(row));
    }

    /// `scopeChainsToRoot()`: whether a scope's Intermediate carries the
    /// current Root's signature — checked by signature, never by name, as
    /// every Root this service builds has the same subject. A scope with
    /// no Intermediate answers true.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn scope_chains_to_root(&self, scope: &str) -> bool {
        let Some(root) = self.service_root() else {
            return true;
        };
        let Some(intermediate) = self
            .raw_row_for(scope)
            .and_then(|r| r.get("intermediate").cloned())
            .filter(|i| !i.is_null())
        else {
            return true;
        };
        let (Ok(root), Ok(int)) = (
            Certificate::from_pem(str_of(&root, "certificatePem")),
            Certificate::from_pem(str_of(&intermediate, "certificatePem")),
        ) else {
            tracing::warn!(
                "pki: the \"{}\" branch could not be checked against the Root, so it is left alone.",
                scope
            );
            return true;
        };
        verify_signature(&int, &root).unwrap_or(true)
    }

    // -----------------------------------------------------------------
    // The algorithms.
    // -----------------------------------------------------------------

    /// `alternativeKeyAlgFrom()`.
    fn alternative_key_alg_from(
        &self,
        asked: Option<&str>,
    ) -> Result<Option<String>, Refusal> {
        let config = self.config();
        let id = asked
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                Some(config.alternative_key_algorithm.clone())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "none".to_string())
            .trim()
            .to_lowercase();
        if id == "none" {
            return Ok(None);
        }
        let known = catalog::alternative_key_algs();
        if !known.contains(&id) {
            return Err(Refusal::new(
                codes::STS_PKI_0200,
                format!(
                    "\"{}\" is not an alternative key algorithm an authority here can hold. \
                     It must be a post-quantum signature algorithm — {} — or \"none\" for a \
                     classical-only authority.",
                    id,
                    known.join(", ")
                ),
            ));
        }
        Ok(Some(id))
    }

    /// `algorithmsFrom()`: what a build would sign with, decided before
    /// any key is made.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn algorithms_from(
        &self,
        key_alg_asked: Option<&str>,
        signature_alg_asked: Option<&str>,
        alt_key_alg_asked: Option<&str>,
    ) -> Result<Chosen, Refusal> {
        let config = self.config();
        let key_id = key_alg_asked
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                Some(config.key_algorithm.clone()).filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| DEFAULT_KEY_ALG.to_string());
        let Some(desc) = key_alg(&key_id) else {
            return Err(Refusal::new(
                codes::STS_PKI_0002,
                format!(
                    "\"{}\" is not a key algorithm this service can generate. It knows {}.",
                    key_id,
                    catalog::key_alg_ids().join(", ")
                ),
            ));
        };
        let producible = desc.signature_algorithms();
        let configured = config.signature_algorithm.trim().to_string();
        let configured_fits = algorithms::sig_alg(&configured)
            .is_some_and(|s| producible.contains(&s.id));
        let sig_id = signature_alg_asked
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| configured_fits.then(|| configured.clone()))
            .unwrap_or_else(|| desc.default_signature_algorithm());
        let Some(sig) = algorithms::sig_alg(&sig_id) else {
            return Err(Refusal::new(
                codes::STS_PKI_0003,
                format!(
                    "\"{}\" is not a signature algorithm this service can produce.",
                    sig_id
                ),
            ));
        };
        if sig.weak && !config.uses_broken_algorithms {
            let strong: Vec<String> = producible
                .iter()
                .filter(|id| !algorithms::sig_alg(id).is_some_and(|s| s.weak))
                .cloned()
                .collect();
            return Err(Refusal::new(
                codes::STS_PKI_0191,
                format!(
                    "\"{}\" signs with SHA-1, which this realm does not use in product mode \
                     (global.mode=product). Choose {}.",
                    sig_id,
                    strong.join(", ")
                ),
            ));
        }
        if !producible.contains(&sig.id) {
            let sentence = if producible.is_empty() {
                format!(
                    "A {} key cannot sign, so it cannot be a certificate authority.",
                    desc.label
                )
            } else {
                format!(
                    "A {} key cannot produce a {} signature. The algorithms this key can sign \
                     with are {}.",
                    desc.label,
                    sig.label,
                    producible.join(", ")
                )
            };
            return Err(Refusal::new(codes::STS_PKI_0004, sentence));
        }
        let alt = self.alternative_key_alg_from(alt_key_alg_asked)?;
        Ok(Chosen {
            key_alg: key_id,
            signature_alg: sig_id,
            alt_key_alg: alt,
        })
    }

    /// `algorithmsForUseCase()`: a use case's own preference (`spiffe`'s
    /// EC P-256) applies only where NOBODY chose an algorithm.
    fn algorithms_for_use_case(
        &self,
        uc: &UseCase,
        chosen: &Chosen,
        asked_key_alg: bool,
    ) -> Chosen {
        let config = self.config();
        let Some(preferred_key) = uc.key_alg else {
            return chosen.clone();
        };
        let configured = config.key_algorithm.clone();
        if asked_key_alg
            || (!configured.is_empty()
                && !config.key_algorithm_defaulted
                && configured != DEFAULT_KEY_ALG)
        {
            return chosen.clone();
        }
        match self.algorithms_from(Some(preferred_key), uc.signature_alg, None)
        {
            Ok(mut preferred) => {
                preferred.alt_key_alg = chosen.alt_key_alg.clone();
                preferred
            }
            Err(r) => {
                tracing::error!(
                    "{}pki: the {} use case prefers \"{}\", which this service cannot use ({}). \
                     Building it with the branch's {} instead.",
                    tag(codes::STS_PKI_0001),
                    uc.label,
                    preferred_key,
                    r.sentence(),
                    chosen.key_alg
                );
                chosen.clone()
            }
        }
    }

    /// `signatureForIssuer()`: the preferred algorithm when the issuer's key
    /// can produce it (and it is not SHA-1 where that is refused), the
    /// issuer key's default otherwise.
    fn signature_for_issuer(
        &self,
        issuer_key_alg: &str,
        preferred: &str,
    ) -> String {
        let config = self.config();
        let desc = key_alg(issuer_key_alg);
        let producible = desc
            .as_ref()
            .map(|d| d.signature_algorithms())
            .unwrap_or_default();
        if let Some(wanted) = algorithms::sig_alg(preferred) {
            if producible.contains(&wanted.id)
                && (!wanted.weak || config.uses_broken_algorithms)
            {
                return preferred.to_string();
            }
        }
        desc.map(|d| d.default_signature_algorithm())
            .unwrap_or_else(|| DEFAULT_SIG_ALG.to_string())
    }

    /// `listenerChainOptions()`: a composite ML-DSA key cannot be on the
    /// TLS listeners' chain — refused where a caller named it, the
    /// classical default where only `pki.keyAlgorithm` did.
    fn listener_chain_key_alg(
        &self,
        asked: Option<&str>,
        label: &str,
        refused: ErrorCode,
        fallback: ErrorCode,
    ) -> Result<Option<String>, Refusal> {
        if let Some(asked) = asked.filter(|s| !s.is_empty()) {
            if is_composite(asked) {
                tracing::warn!(
                    "{}pki: {} was asked for a {} key, which the TLS listeners cannot load. \
                     Nothing was built.",
                    tag(refused),
                    label,
                    asked
                );
                return Err(Refusal::new(
                    refused,
                    format!(
                        "A composite ML-DSA key cannot sign {}: that certificate is on the TLS \
                         listeners' chain, and the TLS library cannot read a composite key, so \
                         the listeners would keep the certificate they have. Choose ML-DSA, \
                         SLH-DSA or a classical key, or a hybrid branch with an alternative \
                         ML-DSA key. Nothing was built.",
                        label
                    ),
                ));
            }
            return Ok(Some(asked.to_string()));
        }
        let config = self.config();
        if !is_composite(&config.key_algorithm) {
            return Ok(None);
        }
        let classical = format!("rsa-{}", config.default_rsa_bits);
        tracing::warn!(
            "{}pki: pki.keyAlgorithm is {}, which the TLS listeners cannot load, so {} is \
             built with {}.",
            tag(fallback),
            config.key_algorithm,
            label,
            classical
        );
        Ok(Some(classical))
    }

    /// `tierYearsFrom()` and `certificateLifetimeProblem()`.
    fn tier_years(
        &self,
        asked: Option<i64>,
        tier: &str,
    ) -> Result<i64, Refusal> {
        let n = asked
            .filter(|n| *n > 0)
            .unwrap_or_else(|| self.config().tier_years(tier));
        if n > 0 && add_years(certificate_instant(None), n).is_none() {
            tracing::info!(
                "{}pki: a lifetime of {} years is not a date a certificate can carry. Nothing \
                 was stored.",
                tag(codes::STS_PKI_0268),
                n
            );
            return Err(Refusal::new(
                codes::STS_PKI_0268,
                format!(
                    "A lifetime of {} years is not a date a certificate can carry. Nothing was \
                     stored.",
                    n
                ),
            ));
        }
        Ok(n)
    }

    // -----------------------------------------------------------------
    // A tier.
    // -----------------------------------------------------------------

    /// `revocationExtensionsFor()`: the issuer's CRL (http and ldap), its
    /// OCSP responder and its certificate.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revocation_extensions_for(&self, scope: &str, ca: &str) -> Json {
        let points = self.distribution_points(scope, ca);
        json!({
            "cRLDistributionPoints": { "present": true, "critical": false,
                "urls": [points.http, points.ldap] },
            "authorityInfoAccess": { "present": true, "critical": false,
                "entries": [
                    { "method": "ocsp", "url": points.ocsp },
                    { "method": "caIssuers", "url": points.ca_issuers },
                ] },
        })
    }

    /// `issueCaTier()`: one certificate authority — a fresh key, a
    /// certificate from its parent (or itself, for the Root) under the
    /// profile's constraints, no longer-lived than the parent, the
    /// parent's distribution points, and an alternative key where the
    /// branch is hybrid.
    fn issue_ca_tier(&self, spec: &CaSpec) -> Result<Json, String> {
        let profile = ext::profile(spec.profile)
            .ok_or_else(|| format!("unknown profile {}", spec.profile))?;
        let parent_key_alg = spec
            .parent
            .as_ref()
            .map(|p| str_of(p, "keyAlg").to_string())
            .unwrap_or_else(|| spec.key_alg.clone());
        let sig_alg =
            self.signature_for_issuer(&parent_key_alg, &spec.signature_alg);
        let years = if spec.years > 0 {
            spec.years
        } else {
            i64::from(profile.years)
        };
        let desc = key_alg(&spec.key_alg).ok_or_else(|| {
            format!("Unknown key algorithm: {}", spec.key_alg)
        })?;
        let (private_pem, public_pem) =
            desc.generate().map_err(|e| e.to_string())?;
        let alt_key_alg = match &spec.alt_key_alg {
            Some(chosen) => chosen.clone(),
            None => self.alternative_key_alg_from(None).unwrap_or(None),
        };
        let alt_pair = match &alt_key_alg {
            Some(id) => Some(
                key_alg(id)
                    .ok_or_else(|| format!("Unknown key algorithm: {}", id))?
                    .generate()
                    .map_err(|e| e.to_string())?,
            ),
            None => None,
        };
        // The alternative signature is the PARENT's alternative key's; the
        // Root signs its own with the key it was just given.
        let alt_signer: Option<(String, String)> = match &spec.parent {
            Some(p) => {
                let (alg, key) =
                    (str_of(p, "altKeyAlg"), str_of(p, "altPrivateKeyPem"));
                (!alg.is_empty() && !key.is_empty())
                    .then(|| (alg.to_string(), key.to_string()))
            }
            None => alt_key_alg
                .clone()
                .zip(alt_pair.as_ref().map(|(private, _)| private.clone())),
        };
        let not_before = certificate_instant(None);
        let mut not_after = add_years(not_before, years)
            .ok_or_else(|| "Invalid time value".to_string())?;
        if let Some(parent) = &spec.parent {
            if let Some(ends) = ms_of(str_of(parent, "notAfter")) {
                if not_after.timestamp_millis() > ends {
                    tracing::warn!(
                        "pki: the {} asked for would outlive the CA that signs it, so it was \
                         shortened to that CA's own expiry ({}).",
                        spec.profile,
                        str_of(parent, "notAfter")
                    );
                    not_after = DateTime::from_timestamp_millis(ends)
                        .unwrap_or(not_after);
                }
            }
        }
        let mut subject = vec![
            json!({ "name": "CN", "value": spec.cn }),
            json!({ "name": "O", "value": spec.organisation }),
        ];
        if !spec.country.is_empty() {
            subject.push(json!({ "name": "C", "value": spec.country }));
        }
        let mut extensions = json!({
            "basicConstraints": { "present": true, "critical": true, "ca": true,
                "pathLen": spec.path_len.map_or(
                    profile.path_len.map_or(Json::Null, Json::from),
                    Json::from) },
            "keyUsage": { "present": true, "critical": true,
                "usages": profile.key_usage },
            "subjectKeyIdentifier": { "present": true },
            "authorityKeyIdentifier": { "present": true },
        });
        if let Some(parent) = &spec.parent {
            let scope = match str_of(parent, "scope") {
                "" => spec.scope.as_str(),
                one => one,
            };
            let ca = match str_of(parent, "useCase") {
                "" => str_of(parent, "tier"),
                one => one,
            };
            merge_into(
                &mut extensions,
                self.revocation_extensions_for(scope, ca),
            );
        }
        let mut issue = json!({
            "subject": subject,
            "subjectPublicKey": public_pem,
            "signatureAlg": sig_alg,
            "profile": spec.profile,
            "notBefore": time::iso(&not_before),
            "notAfter": time::iso(&not_after),
            "issuer": match &spec.parent {
                Some(p) => json!({
                    "certificatePem": str_of(p, "certificatePem"),
                    "privateKeyPem": str_of(p, "privateKeyPem"),
                    "keyAlg": str_of(p, "keyAlg") }),
                None => json!({ "privateKeyPem": private_pem,
                                "keyAlg": spec.key_alg }),
            },
            "extensions": extensions,
        });
        if let Some((_, alt_public)) = &alt_pair {
            issue["subjectAltPublicKey"] = Json::from(alt_public.clone());
        }
        if let Some((alg, key)) = &alt_signer {
            issue["altSignature"] = json!({ "signatureAlg": alg,
                "privateKeyPem": key, "keyAlg": alg });
        }
        let issued = issue_certificate(&issue).map_err(|e| e.to_string())?;
        let subject = if issued.subject.is_empty() {
            spec.cn.clone()
        } else {
            issued.subject.clone()
        };
        let (alt_private, alt_public) = alt_pair
            .map(|(a, b)| (Json::from(a), Json::from(b)))
            .unwrap_or((Json::Null, Json::Null));
        Ok(json!({
            "tier": spec.tier,
            "label": spec.label,
            "useCase": spec.use_case,
            "scope": spec.scope,
            "keyAlg": spec.key_alg,
            "signatureAlg": sig_alg,
            "subject": subject,
            "serialHex": issued.serial_hex,
            "notBefore": time::iso(&not_before),
            "notAfter": time::iso(&not_after),
            "certificatePem": issued.pem,
            "privateKeyPem": private_pem,
            "publicKeyPem": public_pem,
            "altKeyAlg": if alt_private.is_null() { Json::Null }
                         else { Json::from(alt_key_alg.clone()) },
            "altPrivateKeyPem": alt_private,
            "altPublicKeyPem": alt_public,
            "altSignatureAlg": alt_signer.map(|(a, _)| a),
            "thumbprint": der::hex(&sha256(&issued.der)),
            "imported": false,
            "createdAt": now_ms(),
        }))
    }

    // -----------------------------------------------------------------
    // The Root.
    // -----------------------------------------------------------------

    fn build_root_now(&self, options: &BuildOptions) -> Result<Json, Refusal> {
        let key = self.listener_chain_key_alg(
            options.key_alg.as_deref(),
            "the service Root",
            codes::STS_PKI_0272,
            codes::STS_PKI_0273,
        )?;
        let chosen = self.algorithms_from(
            key.as_deref().or(options.key_alg.as_deref()),
            options.signature_alg.as_deref(),
            options.alt_key_alg.as_deref(),
        )?;
        let years = self.tier_years(options.root_years, "root")?;
        let organisation = options
            .organisation
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_ORGANISATION.to_string());
        let country = options.country.clone().unwrap_or_default();
        let root = self
            .issue_ca_tier(&CaSpec {
                tier: "root",
                profile: "root-ca",
                label: "Root CA".to_string(),
                use_case: None,
                scope: SERVICE_SCOPE.to_string(),
                cn: options
                    .common_name
                    .clone()
                    .unwrap_or_else(|| format!("{} Root CA", organisation)),
                organisation: organisation.clone(),
                country: country.clone(),
                key_alg: chosen.key_alg.clone(),
                signature_alg: chosen.signature_alg.clone(),
                alt_key_alg: Some(chosen.alt_key_alg.clone()),
                path_len: None,
                years,
                parent: None,
            })
            .map_err(|e| {
                tracing::error!(
                    "{}pki: the Root CA could not be issued: {}. Nothing was stored.",
                    tag(codes::STS_PKI_0005),
                    e
                );
                Refusal::new(
                    codes::STS_PKI_0005,
                    format!("The Root CA could not be issued: {}. Nothing was stored.", e),
                )
            })?;
        let mut row = self
            .rows
            .get(SERVICE_SCOPE)
            .filter(Json::is_object)
            .unwrap_or_else(|| json!({}));
        merge_into(
            &mut row,
            json!({
                "version": 2, "scope": SERVICE_SCOPE, "root": root,
                "organisation": organisation, "country": country,
                "keyAlg": chosen.key_alg, "signatureAlg": chosen.signature_alg,
                "altKeyAlg": chosen.alt_key_alg, "createdAt": now_ms(),
            }),
        );
        self.rows.attach(SERVICE_SCOPE, Some(&row));
        tracing::info!(
            "pki: THE SERVICE HAS A ROOT CA — {}, {} signed {}{}. Every realm's Intermediate \
             is signed by it, so it is the one anchor an operator installs. {}",
            str_of(&root, "subject"),
            chosen.key_alg,
            chosen.signature_alg,
            match &chosen.alt_key_alg {
                Some(a) => format!(
                    ", with an alternative {} key and signature (hybrid)",
                    a
                ),
                None => ", classical only".to_string(),
            },
            if self.persists() {
                "It is written to the persistence store, sealed."
            } else {
                "It is held in memory only — this service is in development mode, where key \
                 material is generated per start."
            }
        );
        Ok(root)
    }

    /// `ensureRoot()`: builds the Root only if there is none — the one a
    /// 1.x product install stored is READ, never replaced.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ensure_root(&self, options: &BuildOptions) -> Result<Json, Refusal> {
        if let Some(root) = self.service_root() {
            return Ok(root);
        }
        let _one = self.lock_builds();
        if let Some(root) = self.service_root() {
            return Ok(root);
        }
        self.build_root_now(options)
    }

    /// `buildRoot()`: replaces the Root. The branches are left in place
    /// and no longer chain to it until they are rebuilt (`repairBranch()`
    /// rebuilds one on its next use).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn build_root(&self, options: &BuildOptions) -> Result<Json, Refusal> {
        let _one = self.lock_builds();
        self.build_root_now(options)
    }

    // -----------------------------------------------------------------
    // A branch.
    // -----------------------------------------------------------------

    fn build_scope_now(
        &self,
        scope: &str,
        options: &BuildOptions,
    ) -> Result<Json, Refusal> {
        let id = scope_id(scope);
        let kind = scope_kind_of(&id);
        let key = match kind {
            ScopeKind::Process => self.listener_chain_key_alg(
                options.key_alg.as_deref(),
                "the process branch",
                codes::STS_PKI_0272,
                codes::STS_PKI_0273,
            )?,
            ScopeKind::Realm => self.listener_chain_key_alg(
                options.key_alg.as_deref(),
                &format!("the \"{}\" realm's branch", id),
                codes::STS_PKI_0274,
                codes::STS_PKI_0275,
            )?,
        };
        let chosen = self.algorithms_from(
            key.as_deref().or(options.key_alg.as_deref()),
            options.signature_alg.as_deref(),
            options.alt_key_alg.as_deref(),
        )?;
        let intermediate_years =
            self.tier_years(options.intermediate_years, "intermediate")?;
        let issuing_years =
            self.tier_years(options.issuing_years, "issuing")?;
        if self.service_root().is_none() {
            self.build_root_now(options)?;
        }
        let root = self.service_root().ok_or_else(|| {
            Refusal::new(
                codes::STS_PKI_0005,
                "The Root CA could not be issued.",
            )
        })?;
        let service = self.rows.get(SERVICE_SCOPE).unwrap_or(Json::Null);
        let organisation = options
            .organisation
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                Some(str_of(&service, "organisation").to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| DEFAULT_ORGANISATION.to_string());
        let country = options
            .country
            .clone()
            .unwrap_or_else(|| str_of(&service, "country").to_string());
        let existing = self.raw_row_for(&id).unwrap_or_else(|| json!({}));
        let (label, named) = match kind {
            ScopeKind::Process => {
                ("the process".to_string(), "Process".to_string())
            }
            ScopeKind::Realm => (format!("the \"{}\" realm", id), id.clone()),
        };
        let multi_cell = self.config().multi_cell;
        let held_intermediate = existing
            .get("intermediate")
            .filter(|i| !i.is_null())
            .cloned();
        let keep_imported = held_intermediate.as_ref().is_some_and(|i| {
            i.get("imported").and_then(Json::as_bool) == Some(true)
        }) && !options.replace_imported;
        let intermediate = match (keep_imported, held_intermediate.clone()) {
            (true, Some(held)) => held,
            _ => self
                .issue_ca_tier(&CaSpec {
                    tier: "intermediate",
                    profile: "intermediate-ca",
                    label: "Intermediate CA".to_string(),
                    use_case: None,
                    scope: id.clone(),
                    cn: options.intermediate_cn.clone().unwrap_or_else(|| {
                        format!("{} Intermediate CA ({})", organisation, named)
                    }),
                    organisation: organisation.clone(),
                    country: country.clone(),
                    key_alg: chosen.key_alg.clone(),
                    signature_alg: chosen.signature_alg.clone(),
                    alt_key_alg: Some(chosen.alt_key_alg.clone()),
                    path_len: Some(catalog::intermediate_path_len(
                        kind, multi_cell,
                    )),
                    years: intermediate_years,
                    parent: Some(root.clone()),
                })
                .map_err(|e| {
                    tracing::error!(
                        "{}pki: {}'s Intermediate CA could not be issued: {}. Nothing was \
                         stored.",
                        tag(codes::STS_PKI_0006),
                        label,
                        e
                    );
                    Refusal::new(
                        codes::STS_PKI_0006,
                        format!(
                            "The Intermediate CA could not be issued: {}. Nothing was stored.",
                            e
                        ),
                    )
                })?,
        };
        let wanted = use_cases_for(kind, multi_cell);
        let mut issuing = Map::new();
        for uc in &wanted {
            let held = existing.get("issuing").and_then(|i| i.get(uc.id));
            if let Some(held) = held {
                if held.get("imported").and_then(Json::as_bool) == Some(true)
                    && !options.replace_imported
                {
                    issuing.insert(uc.id.to_string(), held.clone());
                    continue;
                }
            }
            let for_this = self.algorithms_for_use_case(
                uc,
                &chosen,
                options.key_alg.is_some(),
            );
            let tier = self
                .issue_ca_tier(&CaSpec {
                    tier: "issuing",
                    profile: "issuing-ca",
                    label: format!("{} CA", uc.label),
                    use_case: Some(uc.id),
                    scope: id.clone(),
                    cn: format!("{} {} ({})", organisation, uc.cn, named),
                    organisation: organisation.clone(),
                    country: country.clone(),
                    key_alg: for_this.key_alg,
                    signature_alg: for_this.signature_alg,
                    alt_key_alg: Some(chosen.alt_key_alg.clone()),
                    path_len: Some(catalog::issuing_path_len(uc.id)),
                    years: issuing_years,
                    parent: Some(intermediate.clone()),
                })
                .map_err(|e| {
                    tracing::error!(
                        "{}pki: {}'s {} Issuing CA could not be issued: {}. Nothing was stored.",
                        tag(codes::STS_PKI_0007),
                        label,
                        uc.label,
                        e
                    );
                    Refusal::new(
                        codes::STS_PKI_0007,
                        format!(
                            "The {} Issuing CA could not be issued: {}. Nothing was stored.",
                            uc.label, e
                        ),
                    )
                })?;
            issuing.insert(uc.id.to_string(), tier);
        }
        // A REBUILT Intermediate supersedes what it replaced: the old
        // Issuing CAs on the old Intermediate's list, the old Intermediate
        // on the Root's.
        let rebuilt = held_intermediate
            .as_ref()
            .is_some_and(|held| held != &intermediate);
        if let (true, Some(old)) = (rebuilt, &held_intermediate) {
            if let Some(old_issuing) =
                existing.get("issuing").and_then(Json::as_object)
            {
                for tier in old_issuing.values() {
                    self.supersede(
                        &id,
                        "intermediate",
                        tier,
                        "its Intermediate CA was rebuilt",
                    );
                }
            }
            self.supersede(
                SERVICE_SCOPE,
                "root",
                old,
                &format!("the \"{}\" branch was rebuilt", id),
            );
        }
        let base = self.raw_row_for(&id).unwrap_or(existing);
        let objects = base.get("objects").cloned().unwrap_or_else(|| json!([]));
        let mut row = base;
        if !row.is_object() {
            row = json!({});
        }
        let created = row
            .get("createdAt")
            .filter(|c| !c.is_null())
            .cloned()
            .unwrap_or_else(|| Json::from(now_ms()));
        merge_into(
            &mut row,
            json!({
                "version": 2,
                "scope": id,
                "realm": if kind == ScopeKind::Realm { Json::from(id.clone()) }
                         else { Json::Null },
                "createdAt": created,
                "keyAlg": chosen.key_alg,
                "signatureAlg": chosen.signature_alg,
                "altKeyAlg": chosen.alt_key_alg,
                "organisation": organisation,
                "country": country,
                "intermediate": intermediate,
                "issuing": issuing,
                "objects": objects,
                "issuedCount": 0,
            }),
        );
        if let Some(map) = row.as_object_mut() {
            map.remove("tiers");
        }
        self.save_row(&id, &row);
        tracing::info!(
            "pki: {} has a certificate authority branch: an Intermediate CA signed by the \
             service Root, and {} Issuing CA(s) — {}. {} keys signed {}{}",
            label,
            wanted.len(),
            wanted.iter().map(|u| u.label).collect::<Vec<_>>().join(", "),
            chosen.key_alg,
            chosen.signature_alg,
            match &chosen.alt_key_alg {
                Some(a) => format!(", each with an alternative {} key (hybrid).", a),
                None => ", classical only.".to_string(),
            }
        );
        Ok(row)
    }

    /// `buildScope()`: a scope's whole branch, replacing what it held but
    /// an imported tier.
    #[tracing::instrument(level = "debug", skip(self, options))]
    pub fn build_scope(
        &self,
        scope: &str,
        options: &BuildOptions,
    ) -> Result<Json, Refusal> {
        let _one = self.lock_builds();
        self.build_scope_now(scope, options)
    }

    /// `repairBranch()`: rebuilds a branch that does not chain to the
    /// current Root, unless another caller already did.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn repair_branch(&self, scope: &str) -> Result<(), Refusal> {
        let _one = self.lock_builds();
        if self.scope_chains_to_root(scope) {
            return Ok(());
        }
        self.build_scope_now(scope, &BuildOptions::default())
            .map(|_| ())
    }

    /// `ensureScope()`: the branch, built only where it is missing —
    /// TOPPED UP where only `pathLen: 0` use cases are, so a stored branch
    /// gains an authority added since without anything being replaced.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn ensure_scope(&self, scope: &str) -> Result<Json, Refusal> {
        let id = scope_id(scope);
        let multi_cell = self.config().multi_cell;
        let wanted = use_cases_for(scope_kind_of(&id), multi_cell);
        let complete = |row: &Option<Json>| {
            row.as_ref().is_some_and(|r| {
                r.get("intermediate").is_some_and(|i| !i.is_null())
                    && wanted.iter().all(|uc| {
                        r.get("issuing")
                            .and_then(|i| i.get(uc.id))
                            .is_some_and(|t| !t.is_null())
                    })
            })
        };
        let row = self.raw_row_for(&id);
        if complete(&row) {
            return Ok(row.unwrap_or(Json::Null));
        }
        let _one = self.lock_builds();
        let row = self.raw_row_for(&id);
        if complete(&row) {
            return Ok(row.unwrap_or(Json::Null));
        }
        let missing: Vec<&UseCase> = wanted
            .iter()
            .copied()
            .filter(|uc| {
                !row.as_ref()
                    .and_then(|r| r.get("issuing"))
                    .and_then(|i| i.get(uc.id))
                    .is_some_and(|t| !t.is_null())
            })
            .collect();
        let has_branch = row.as_ref().is_some_and(|r| {
            r.get("intermediate").is_some_and(|i| !i.is_null())
                && r.get("issuing").is_some_and(Json::is_object)
        });
        if has_branch
            && missing.len() < wanted.len()
            && missing.iter().all(|uc| uc.path_len == 0)
        {
            return self.top_up_scope_now(&id, &missing);
        }
        let options = BuildOptions {
            organisation: Some(self.config().organisation)
                .filter(|s| !s.is_empty()),
            ..BuildOptions::default()
        };
        self.build_scope_now(&id, &options)
    }

    fn top_up_scope_now(
        &self,
        id: &str,
        missing: &[&UseCase],
    ) -> Result<Json, Refusal> {
        let row = self.raw_row_for(id).unwrap_or(Json::Null);
        let kind = scope_kind_of(id);
        let organisation = match str_of(&row, "organisation") {
            "" => DEFAULT_ORGANISATION.to_string(),
            one => one.to_string(),
        };
        let named = match kind {
            ScopeKind::Process => "Process".to_string(),
            ScopeKind::Realm => id.to_string(),
        };
        let branch = Chosen {
            key_alg: str_of(&row, "keyAlg").to_string(),
            signature_alg: str_of(&row, "signatureAlg").to_string(),
            alt_key_alg: row
                .get("altKeyAlg")
                .and_then(Json::as_str)
                .map(str::to_string),
        };
        let issuing_years = self.tier_years(None, "issuing")?;
        let mut made = Map::new();
        for uc in missing {
            let for_this = self.algorithms_for_use_case(uc, &branch, false);
            let tier = self
                .issue_ca_tier(&CaSpec {
                    tier: "issuing",
                    profile: "issuing-ca",
                    label: format!("{} CA", uc.label),
                    use_case: Some(uc.id),
                    scope: id.to_string(),
                    cn: format!("{} {} ({})", organisation, uc.cn, named),
                    organisation: organisation.clone(),
                    country: str_of(&row, "country").to_string(),
                    key_alg: for_this.key_alg,
                    signature_alg: for_this.signature_alg,
                    alt_key_alg: Some(branch.alt_key_alg.clone()),
                    path_len: Some(catalog::issuing_path_len(uc.id)),
                    years: issuing_years,
                    parent: row.get("intermediate").cloned(),
                })
                .map_err(|e| {
                    tracing::error!(
                        "{}pki: the \"{}\" branch was missing its {} Issuing CA and it could \
                         not be added: {}. Nothing was stored.",
                        tag(codes::STS_PKI_0007),
                        id,
                        uc.label,
                        e
                    );
                    Refusal::new(
                        codes::STS_PKI_0007,
                        format!(
                            "The {} Issuing CA could not be added to this branch: {}. Nothing \
                             was stored.",
                            uc.label, e
                        ),
                    )
                })?;
            made.insert(uc.id.to_string(), tier);
        }
        let mut fresh = self.raw_row_for(id).unwrap_or(row);
        let names: Vec<String> = made.keys().cloned().collect();
        if let Some(issuing) =
            fresh.get_mut("issuing").and_then(Json::as_object_mut)
        {
            issuing.extend(made);
        }
        self.save_row(id, &fresh);
        tracing::info!(
            "pki: the \"{}\" branch was built before {} use case(s) existed, so {} was added \
             under its existing Intermediate CA. Nothing already issued was replaced.",
            id,
            names.len(),
            names.join(", ")
        );
        Ok(fresh)
    }

    // -----------------------------------------------------------------
    // Reading the hierarchy.
    // -----------------------------------------------------------------

    /// `rawChainFor()`'s three: the Root, the Intermediate and the
    /// scope's primary Issuing CA (`tls` for the process, `assertions`
    /// for a realm).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn raw_chain_for(&self, scope: &str) -> Option<[Json; 3]> {
        let id = scope_id(scope);
        let root = self.service_root()?;
        let row = self.raw_row_for(&id)?;
        let intermediate =
            row.get("intermediate").filter(|i| !i.is_null())?.clone();
        let primary = row
            .get("issuing")?
            .get(catalog::primary_use_case_for(&id))?
            .clone();
        Some([root, intermediate, primary])
    }

    /// `hasChain()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn has_chain(&self, scope: &str) -> bool {
        self.raw_chain_for(scope).is_some()
    }

    /// `chainPemFor()`: the primary Issuing CA, then the Intermediate.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn chain_pem_for(&self, scope: &str) -> Vec<String> {
        self.raw_chain_for(scope)
            .map(|[_, i, p]| {
                vec![
                    str_of(&p, "certificatePem").to_string(),
                    str_of(&i, "certificatePem").to_string(),
                ]
            })
            .unwrap_or_default()
    }

    /// `trustAnchorsFor()`: the Root, where the scope holds a chain.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn trust_anchors_for(&self, scope: &str) -> Vec<String> {
        self.raw_chain_for(scope)
            .map(|[r, _, _]| vec![str_of(&r, "certificatePem").to_string()])
            .unwrap_or_default()
    }

    /// `chainThroughRoot()`: a leaf and its chain, with the Root the top
    /// of the chain is signed by (the service's, or one of `anchors`)
    /// appended; bare base64 is read as a certificate.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn chain_through_root(
        &self,
        certificate: &str,
        chain: &[String],
        anchors: &[String],
        without_root: bool,
    ) -> Vec<String> {
        let as_pem = |text: &str| -> String {
            let value = text.trim();
            if value.is_empty() {
                return String::new();
            }
            if value.contains("-----BEGIN") {
                return text.to_string();
            }
            let b64: String = value.split_whitespace().collect();
            let lines: Vec<String> = b64
                .as_bytes()
                .chunks(64)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect();
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            )
        };
        let leaf = as_pem(certificate);
        let chain: Vec<String> = chain
            .iter()
            .map(|p| as_pem(p))
            .filter(|p| !p.is_empty() && *p != leaf)
            .collect();
        let mut pems = if leaf.is_empty() {
            chain.clone()
        } else {
            std::iter::once(leaf).chain(chain.iter().cloned()).collect()
        };
        if chain.is_empty() || without_root {
            return pems;
        }
        let mut candidates: Vec<String> = anchors.to_vec();
        if let Some(root) = self.service_root() {
            candidates.push(str_of(&root, "certificatePem").to_string());
        }
        let Some(top) =
            chain.last().and_then(|p| Certificate::from_pem(p).ok())
        else {
            return pems;
        };
        let found = candidates.into_iter().find(|pem| {
            !pem.is_empty()
                && !pems.contains(pem)
                && Certificate::from_pem(pem)
                    .ok()
                    .and_then(|anchor| verify_signature(&top, &anchor).ok())
                    .unwrap_or(false)
        });
        if let Some(root) = found {
            pems.push(root);
        }
        pems
    }

    /// `describeIssuer()`: a use case's Issuing CA with its chain and Root,
    /// for a caller that signs under it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn describe_issuer(
        &self,
        scope: &str,
        use_case_id: &str,
    ) -> Option<Json> {
        let id = scope_id(scope);
        let row = self.raw_row_for(&id)?;
        let ca = row.get("issuing")?.get(use_case_id)?.clone();
        let intermediate = row.get("intermediate").filter(|i| !i.is_null())?;
        let root = self.service_root()?;
        Some(json!({
            "scope": id,
            "useCase": use_case_id,
            "subject": ca["subject"],
            "serialHex": ca["serialHex"],
            "keyAlg": ca["keyAlg"],
            "signatureAlg": self.signature_for_issuer(
                str_of(&ca, "keyAlg"), str_of(&ca, "signatureAlg")),
            "signedWith": ca["signatureAlg"],
            "notBefore": ca["notBefore"],
            "notAfter": ca["notAfter"],
            "thumbprint": ca["thumbprint"],
            "imported": ca.get("imported").and_then(Json::as_bool)
                .unwrap_or(false),
            "certificatePem": ca["certificatePem"],
            "chainPem": [ca["certificatePem"],
                         intermediate["certificatePem"]],
            "intermediate": {
                "subject": intermediate["subject"],
                "notAfter": intermediate["notAfter"],
                "thumbprint": intermediate["thumbprint"],
                "certificatePem": intermediate["certificatePem"] },
            "root": {
                "subject": root["subject"],
                "serialHex": root["serialHex"],
                "notBefore": root["notBefore"],
                "notAfter": root["notAfter"],
                "thumbprint": root["thumbprint"],
                "certificatePem": root["certificatePem"] },
        }))
    }

    /// The tier a CA id names in a scope (`authorityFor()`'s `tier`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn tier_for(&self, scope: &str, ca: &str) -> Option<Json> {
        if ca == "root" {
            return self.service_root();
        }
        let row = self.raw_row_for(scope)?;
        let tier = if ca == "intermediate" {
            row.get("intermediate")
        } else {
            row.get("issuing").and_then(|i| i.get(ca))
        };
        tier.filter(|t| !t.is_null()).cloned()
    }

    // -----------------------------------------------------------------
    // Issuing.
    // -----------------------------------------------------------------

    /// `issueUnder()`: a leaf under a use case's Issuing CA, NOT recorded —
    /// for a caller that owns what comes out (`spiffe_ca.ts`, a cell's
    /// channel leaf). A branch that no longer chains to the Root is
    /// rebuilt first; a leaf is never longer-lived than its CA.
    #[tracing::instrument(level = "debug", skip(self, spec))]
    pub fn issue_under(
        &self,
        scope: &str,
        use_case_id: &str,
        spec: &LeafSpec,
    ) -> Result<Issued, Refusal> {
        let id = scope_id(scope);
        let Some(uc) = use_case(use_case_id) else {
            return Err(unknown_use_case(use_case_id));
        };
        if spec.public_key_pem.is_empty() {
            return Err(Refusal::new(
                codes::STS_PKI_0026,
                "A certificate is issued OVER a public key. None was given.",
            ));
        }
        if !self.scope_chains_to_root(&id) {
            tracing::warn!(
                "pki: the \"{}\" branch does not chain to this service's Root CA, so it is \
                 being rebuilt before anything is issued from it.",
                id
            );
            self.repair_branch(&id).map_err(|r| Refusal {
                code: codes::STS_PKI_0023,
                errors: r.errors,
            })?;
        }
        let row = self.raw_row_for(&id).unwrap_or(Json::Null);
        let ca = row.get("issuing").and_then(|i| i.get(uc.id)).cloned();
        let intermediate =
            row.get("intermediate").filter(|i| !i.is_null()).cloned();
        let (Some(ca), Some(intermediate)) = (ca, intermediate) else {
            return Err(Refusal::new(
                codes::STS_PKI_0009,
                format!(
                    "The \"{}\" scope has no {} Issuing CA. Build the hierarchy on /admin/pki \
                     first.",
                    id, uc.label
                ),
            ));
        };
        let not_before = certificate_instant(spec.not_before_ms);
        let mut not_after = certificate_instant(Some(spec.not_after_ms));
        if let Some(ends) = ms_of(str_of(&ca, "notAfter")) {
            if not_after.timestamp_millis() > ends {
                not_after = certificate_instant(Some(ends));
            }
        }
        let mut issue = json!({
            "subject": spec.subject,
            "subjectPublicKey": spec.public_key_pem,
            "signatureAlg": self.signature_for_issuer(
                str_of(&ca, "keyAlg"), str_of(&ca, "signatureAlg")),
            "profile": spec.profile.clone()
                .unwrap_or_else(|| "digital-signature".to_string()),
            "notBefore": time::iso(&not_before),
            "notAfter": time::iso(&not_after),
            "issuer": { "certificatePem": ca["certificatePem"],
                        "privateKeyPem": ca["privateKeyPem"],
                        "keyAlg": ca["keyAlg"] },
            "extensions": spec.extensions.clone().unwrap_or_else(|| json!({})),
        });
        add_alternative_signature(&mut issue, &ca);
        let issued = issue_certificate(&issue).map_err(|e| {
            tracing::error!(
                "{}pki: a {} certificate could not be issued: {}",
                tag(codes::STS_PKI_0024),
                uc.label,
                e
            );
            Refusal::new(
                codes::STS_PKI_0024,
                format!("That certificate could not be issued: {}", e),
            )
        })?;
        let issuer_chain = vec![
            str_of(&ca, "certificatePem").to_string(),
            str_of(&intermediate, "certificatePem").to_string(),
        ];
        Ok(Issued {
            certificate_pem: issued.pem.clone(),
            certificate_der: issued.der.clone(),
            subject: issued.subject,
            serial_hex: issued.serial_hex,
            not_before: time::iso(&not_before),
            not_after: time::iso(&not_after),
            signature_alg: str_of(&ca, "signatureAlg").to_string(),
            chain_pem: std::iter::once(issued.pem)
                .chain(issuer_chain.iter().cloned())
                .collect(),
            issuer_chain_pem: issuer_chain,
        })
    }

    /// `issueEnrolled()`: the door ACME, EST and SCEP sign through
    /// (`cert_enrollment.ts`, rule 3ag) — `issueUnder()` with the profile's
    /// extensions, the key identifiers, the holder's names and the family
    /// CA's distribution points, and a record in the row's
    /// `issuedKeyPairs` so OCSP answers `good` for it.
    #[tracing::instrument(level = "debug", skip(self, spec))]
    pub fn issue_enrolled(
        &self,
        scope: &str,
        use_case_id: &str,
        spec: &EnrolledSpec,
    ) -> Result<Issued, Refusal> {
        let id = scope_id(scope);
        let uc = use_case(use_case_id)
            .filter(|u| u.scope == ScopeKind::Realm)
            .ok_or_else(|| {
                Refusal::new(
                    codes::STS_PKI_0022,
                    format!(
                        "\"{}\" is not a realm use case this service issues enrolled \
                         certificates from.",
                        use_case_id
                    ),
                )
            })?;
        if spec.public_key_pem.is_empty() || spec.profile.is_empty() {
            return Err(Refusal::new(
                codes::STS_PKI_0026,
                "An enrolled certificate is issued over a public key and a profile, and one of \
                 them was not given.",
            ));
        }
        if !self.has_root() {
            return Err(Refusal::new(
                codes::STS_PKI_0009,
                "This service has no Root CA, so nothing can be issued. Build the hierarchy on \
                 /admin/pki first.",
            ));
        }
        let has_ca = self.raw_row_for(&id).is_some_and(|r| {
            r.get("intermediate").is_some_and(|i| !i.is_null())
                && r.get("issuing").and_then(|i| i.get(uc.id)).is_some()
        });
        if !has_ca {
            self.ensure_scope(&id).map_err(|r| Refusal {
                code: codes::STS_PKI_0023,
                errors: r.errors,
            })?;
        }
        let mut extensions = ext::default_extensions(&spec.profile);
        merge_into(
            &mut extensions,
            json!({
                "subjectKeyIdentifier": { "present": true, "critical": false },
                "authorityKeyIdentifier": { "present": true, "critical": false,
                    "includeIssuerAndSerial": false },
                "subjectAltName": { "present": !spec.subject_alt_name.is_empty(),
                    "critical": false, "names": spec.subject_alt_name },
            }),
        );
        merge_into(&mut extensions, self.revocation_extensions_for(&id, uc.id));
        let now = now_ms();
        let issued = self.issue_under(
            &id,
            uc.id,
            &LeafSpec {
                subject: spec.subject.clone(),
                public_key_pem: spec.public_key_pem.clone(),
                profile: Some(spec.profile.clone()),
                not_before_ms: None,
                not_after_ms: now + spec.days.max(1) * 86_400_000,
                extensions: Some(extensions),
            },
        )?;
        let mut current = self.raw_row_for(&id).unwrap_or_else(|| json!({}));
        let now_text = DateTime::from_timestamp_millis(now)
            .map(|t| time::iso(&t))
            .unwrap_or_default();
        let mut register: Vec<Json> = current
            .get("issuedKeyPairs")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|one| {
                ms_of(str_of(one, "notAfter")).is_some_and(|t| t > now)
            })
            .collect();
        register.push(json!({
            "serialHex": issued.serial_hex,
            "subject": issued.subject,
            "notAfter": issued.not_after,
            "identifier": spec.identifier,
            "subjectKind": spec.subject_kind,
            "holderSubject": spec.holder_subject,
            "purpose": format!("enrolled:{}", spec.profile),
            "useCase": uc.id,
            "issuedAt": now_text,
        }));
        let count = current
            .get("issuedCount")
            .and_then(Json::as_i64)
            .unwrap_or(0);
        current["issuedKeyPairs"] = Json::Array(register);
        current["issuedCount"] = Json::from(count + 1);
        self.save_row(&id, &current);
        tracing::info!(
            "pki: a {} certificate was issued from the \"{}\" realm's {} Issuing CA for \"{}\". \
             serial={}, expires {}.",
            spec.profile,
            id,
            uc.label,
            spec.identifier,
            issued.serial_hex,
            issued.not_after
        );
        Ok(issued)
    }

    /// `certify()`: a certificate over one of this service's own keys
    /// under a use case's Issuing CA, recorded as `certs["<use>:<slot>"]`
    /// (or `@<kid>` for a generation's), the slot's earlier certificate
    /// kept in the register as DISPLACED.
    #[tracing::instrument(level = "debug", skip(self, spec))]
    pub fn certify(
        &self,
        scope: &str,
        use_case_id: &str,
        spec: &CertifySpec,
    ) -> Result<Json, Refusal> {
        let id = scope_id(scope);
        let Some(uc) = use_case(use_case_id) else {
            return Err(unknown_use_case(use_case_id));
        };
        if !self.scope_chains_to_root(&id) {
            tracing::warn!(
                "pki: the \"{}\" branch does not chain to this service's Root CA — a Root was \
                 replaced without its branches being rebuilt. Rebuilding the branch before \
                 issuing.",
                id
            );
            self.repair_branch(&id).map_err(|r| {
                tracing::error!(
                    "{}pki: that branch could not be rebuilt ({}), so nothing was certified.",
                    tag(codes::STS_PKI_0023),
                    r.sentence()
                );
                Refusal {
                    code: codes::STS_PKI_0023,
                    errors: r.errors,
                }
            })?;
        }
        let row = self.raw_row_for(&id).unwrap_or(Json::Null);
        let Some(ca) = row.get("issuing").and_then(|i| i.get(uc.id)).cloned()
        else {
            return Err(Refusal::new(
                codes::STS_PKI_0009,
                format!(
                    "The \"{}\" scope has no {} Issuing CA. Build the hierarchy on /admin/pki \
                     first.",
                    id, uc.label
                ),
            ));
        };
        let sig_alg = self.signature_for_issuer(
            str_of(&ca, "keyAlg"),
            str_of(&ca, "signatureAlg"),
        );
        let days = spec
            .days
            .filter(|d| *d > 0)
            .unwrap_or_else(|| self.config().leaf_days);
        let not_before = certificate_instant(None);
        let mut not_after = not_before + Duration::days(days);
        if let Some(ends) = ms_of(str_of(&ca, "notAfter")) {
            if not_after.timestamp_millis() > ends {
                not_after =
                    DateTime::from_timestamp_millis(ends).unwrap_or(not_after);
            }
        }
        let organisation = match str_of(&row, "organisation") {
            "" => DEFAULT_ORGANISATION.to_string(),
            one => one.to_string(),
        };
        let mut subject = vec![
            json!({ "name": "CN", "value": spec.common_name.clone()
                .unwrap_or_else(|| spec.slot.clone()) }),
            json!({ "name": "O", "value": organisation }),
        ];
        if !str_of(&row, "country").is_empty() {
            subject.push(json!({ "name": "C", "value": row["country"] }));
        }
        let mut extensions = json!({
            "basicConstraints": { "present": true, "critical": true, "ca": false },
            "keyUsage": { "present": true, "critical": true,
                "usages": spec.key_usage.clone().unwrap_or_else(|| vec![
                    "digitalSignature".to_string(),
                    "nonRepudiation".to_string()]) },
            "subjectKeyIdentifier": { "present": true },
            "authorityKeyIdentifier": { "present": true },
        });
        merge_into(&mut extensions, self.revocation_extensions_for(&id, uc.id));
        if let Some(more) = &spec.extensions {
            merge_into(&mut extensions, more.clone());
        }
        let mut issue = json!({
            "subject": subject,
            "subjectPublicKey": spec.public_key_pem,
            "signatureAlg": sig_alg,
            "profile": spec.profile.clone()
                .unwrap_or_else(|| "digital-signature".to_string()),
            "notBefore": time::iso(&not_before),
            "notAfter": time::iso(&not_after),
            "issuer": { "certificatePem": ca["certificatePem"],
                        "privateKeyPem": ca["privateKeyPem"],
                        "keyAlg": ca["keyAlg"] },
            "extensions": extensions,
        });
        if let Some(alt) = &spec.alt_public_key_pem {
            issue["subjectAltPublicKey"] = Json::from(alt.clone());
        }
        add_alternative_signature(&mut issue, &ca);
        let issued = issue_certificate(&issue).map_err(|e| {
            tracing::error!(
                "{}pki: the {} certificate for \"{}\" could not be issued: {}",
                tag(codes::STS_PKI_0024),
                uc.label,
                spec.slot,
                e
            );
            Refusal::new(
                codes::STS_PKI_0024,
                format!("That certificate could not be issued: {}", e),
            )
        })?;
        let mut record = json!({
            "slot": spec.slot,
            "useCase": uc.id,
            "scope": id,
            "label": spec.label.clone().unwrap_or_else(|| spec.slot.clone()),
            "alg": spec.alg,
            "keyAlg": spec.key_alg,
            "signatureAlg": sig_alg,
            "subject": issued.subject,
            "serialHex": issued.serial_hex,
            "notBefore": time::iso(&not_before),
            "notAfter": time::iso(&not_after),
            "certificatePem": issued.pem,
            "chainPem": [ca["certificatePem"],
                         row["intermediate"]["certificatePem"]],
            "thumbprint": der::hex(&sha256(&issued.der)),
            "subjectPublicKeyPem": spec.public_key_pem,
            "subjectKeyFingerprint": thumbprint_of(&spec.public_key_pem),
            "altPublicKeyPem": spec.alt_public_key_pem,
            "pinned": false,
            "createdAt": now_ms(),
        });
        if let Some(holder) = &spec.holder_subject {
            record["holderSubject"] = Json::from(holder.clone());
        }
        if spec.profile.is_some()
            || spec.key_usage.is_some()
            || spec.extensions.is_some()
        {
            record["issuedAs"] = json!({
                "profile": spec.profile.clone().unwrap_or_default(),
                "keyUsage": spec.key_usage,
                "extensions": spec.extensions,
            });
        }
        if let Some(kid) = &spec.kid {
            record["kid"] = Json::from(kid.clone());
        }
        let mut fresh = self.raw_row_for(&id).unwrap_or_else(|| json!({}));
        let slot_key = match (&spec.kid, spec.generation_slot) {
            (Some(kid), true) => format!("{}:{}@{}", uc.id, spec.slot, kid),
            _ => format!("{}:{}", uc.id, spec.slot),
        };
        if !fresh.get("certs").is_some_and(Json::is_object) {
            fresh["certs"] = json!({});
        }
        let displaced = fresh["certs"].get(&slot_key).cloned();
        if let Some(displaced) = displaced {
            let old = str_of(&displaced, "serialHex");
            if !old.is_empty()
                && super::merge::normal_serial(old)
                    != super::merge::normal_serial(&issued.serial_hex)
            {
                let mut register: Vec<Json> = fresh
                    .get("issuedKeyPairs")
                    .and_then(Json::as_array)
                    .cloned()
                    .unwrap_or_default();
                let wanted = super::merge::normal_serial(old);
                if !register.iter().any(|one| {
                    super::merge::normal_serial(str_of(one, "serialHex"))
                        == wanted
                }) {
                    register.push(super::merge::displaced_record(
                        &format!("{}:{}", uc.id, spec.slot),
                        &displaced,
                        now_ms(),
                    ));
                    fresh["issuedKeyPairs"] =
                        Json::Array(super::merge::trim_published(register));
                }
            }
        }
        fresh["certs"][slot_key] = record.clone();
        self.save_row(&id, &fresh);
        Ok(record)
    }

    /// `certificatesFor()`: the slot certificates of one use case, newest
    /// first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn certificates_for(
        &self,
        scope: &str,
        use_case_id: &str,
    ) -> Vec<Json> {
        let row = self.raw_row_for(scope).unwrap_or(Json::Null);
        let prefix = format!("{}:", use_case_id);
        let mut out: Vec<Json> = row
            .get("certs")
            .and_then(Json::as_object)
            .map(|certs| {
                certs
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(_, v)| v.clone())
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| {
            let created = |v: &Json| {
                v.get("createdAt").and_then(Json::as_f64).unwrap_or(0.0)
            };
            created(b).total_cmp(&created(a))
        });
        out
    }

    /// `issuedKeyPairsFor()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn issued_key_pairs_for(
        &self,
        scope: &str,
        use_case_id: &str,
    ) -> Vec<Json> {
        self.raw_row_for(scope)
            .and_then(|r| {
                r.get("issuedKeyPairs").and_then(Json::as_array).cloned()
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|one| str_of(one, "useCase") == use_case_id)
            .collect()
    }

    /// `objects()`: the stored objects of the Certificate Workbench.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn objects(&self, scope: &str) -> Vec<Json> {
        self.raw_row_for(scope)
            .and_then(|r| r.get("objects").and_then(Json::as_array).cloned())
            .unwrap_or_default()
    }

    /// `start()`: the Root (read where one is stored, built where none
    /// is), the process branch and each realm's — every failure said with
    /// its code, none fatal, as a service with no hierarchy self-signs.
    /// `pki.autoBuild=false` builds nothing.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn start(&self, realm_ids: &[String]) -> StartReport {
        let config = self.config();
        if !config.auto_build {
            tracing::info!(
                "pki: `pki.autoBuild` is off, so no certificate authority is built at startup \
                 and this service's own keys are self-signed until somebody presses Build on \
                 /admin/pki."
            );
            return StartReport::default();
        }
        let options = BuildOptions {
            organisation: Some(config.organisation.clone())
                .filter(|s| !s.is_empty()),
            ..BuildOptions::default()
        };
        if let Err(r) = self.ensure_root(&options) {
            tracing::error!(
                "{}pki: THE SERVICE HAS NO ROOT CA — {} Every key this service holds will be \
                 self-signed. Nothing else is affected.",
                tag(codes::STS_PKI_0048),
                r.sentence()
            );
            return StartReport {
                built: false,
                branches: 0,
                errors: r.errors,
            };
        }
        let mut errors = Vec::new();
        if let Err(r) = self.ensure_scope(PROCESS_SCOPE) {
            tracing::error!(
                "{}pki: the process branch could not be built — {}",
                tag(codes::STS_PKI_0049),
                r.sentence()
            );
            errors.extend(r.errors);
        }
        let mut realms: Vec<String> =
            realm_ids.iter().map(|r| scope_id(r)).collect();
        if !realms.iter().any(|r| r == catalog::DEFAULT_REALM) {
            realms.insert(0, catalog::DEFAULT_REALM.to_string());
        }
        let mut branches = 0;
        for realm in &realms {
            match self.ensure_scope(realm) {
                Ok(_) => branches += 1,
                Err(r) => {
                    tracing::error!(
                        "{}pki: the \"{}\" realm's branch could not be built — {}",
                        tag(codes::STS_PKI_0050),
                        realm,
                        r.sentence()
                    );
                    errors.extend(r.errors);
                }
            }
        }
        tracing::info!(
            "pki: the certificate authority is ready — one Root CA for the service, a process \
             Intermediate, and {} realm branch(es).",
            branches
        );
        StartReport {
            built: true,
            branches,
            errors,
        }
    }
}

/// What `start()` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartReport {
    pub built: bool,
    pub branches: usize,
    pub errors: Vec<String>,
}

fn unknown_use_case(id: &str) -> Refusal {
    Refusal::new(
        codes::STS_PKI_0022,
        format!(
            "\"{}\" is not a use case this service issues for. They are {}.",
            id,
            catalog::USE_CASES
                .iter()
                .map(|u| u.id)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
}

/// `alternativeSignatureBy(ca)`: a hybrid authority signs with its
/// alternative key too.
fn add_alternative_signature(issue: &mut Json, ca: &Json) {
    let (alg, key) = (str_of(ca, "altKeyAlg"), str_of(ca, "altPrivateKeyPem"));
    if !alg.is_empty() && !key.is_empty() {
        issue["altSignature"] = json!({ "signatureAlg": alg,
            "privateKeyPem": key, "keyAlg": alg });
    }
}

/// `Object.assign(target, source)` for two JSON objects.
#[tracing::instrument(level = "debug", skip_all)]
pub fn merge_into(target: &mut Json, source: Json) {
    if let (Some(t), Json::Object(s)) = (target.as_object_mut(), source) {
        for (k, v) in s {
            t.insert(k, v);
        }
    }
}

/// `listenerUnreadableKeyAlg()`: a composite ML-DSA key.
#[tracing::instrument(level = "debug")]
pub fn is_composite(key_alg: &str) -> bool {
    sts_crypto::pq_x509::alg(key_alg)
        .is_some_and(|a| a.family == sts_crypto::pq_x509::Family::Composite)
}

/// A certificate PEM's DER, PEM'd again with the label given.
#[tracing::instrument(level = "debug", skip_all)]
pub fn reframe(pem: &str, label: &str) -> String {
    der_to_pem(&pem_to_der(pem).unwrap_or_default(), label)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use openssl::x509::{X509Crl, X509};

    use super::*;
    use crate::authority::rows::MemoryRows;

    fn authority() -> Arc<Authority> {
        Authority::new(Arc::new(MemoryRows::new()), PkiConfig::development())
    }

    fn public_pem() -> String {
        let key = openssl::pkey::PKey::from_rsa(
            openssl::rsa::Rsa::generate(2048).unwrap(),
        )
        .unwrap();
        String::from_utf8(key.public_key_to_pem().unwrap()).unwrap()
    }

    #[test]
    fn development_builds_the_tree_and_publishes_what_it_revokes() {
        let a = authority();
        let started = a.start(&["acme".to_string()]);
        assert!(started.built, "{:?}", started);
        assert_eq!(started.branches, 2);
        let root = a.service_root().unwrap();
        assert_eq!(root["subject"], "CN=iya-sts Root CA, O=iya-sts");
        let process = a.raw_row_for(PROCESS_SCOPE).unwrap();
        assert_eq!(
            process["issuing"]["tls"]["subject"],
            "CN=iya-sts TLS Issuing CA (Process), O=iya-sts"
        );
        let realm = a.raw_row_for("default").unwrap();
        assert_eq!(realm["issuing"]["spiffe"]["keyAlg"], "ec-p256");
        assert_eq!(realm["issuing"].as_object().unwrap().len(), 13);
        // Read, not rebuilt.
        let again = a.ensure_scope("default").unwrap();
        assert_eq!(again["intermediate"], realm["intermediate"]);

        let issued = a
            .issue_enrolled(
                "",
                "acme",
                &EnrolledSpec {
                    subject: json!([{ "name": "CN", "value": "x" }]),
                    public_key_pem: public_pem(),
                    profile: "digital-signature".into(),
                    days: 3,
                    ..EnrolledSpec::default()
                },
            )
            .unwrap();
        assert!(a.issued_here("default", "acme", &issued.serial_hex));
        let leaf = X509::from_pem(issued.certificate_pem.as_bytes()).unwrap();
        let ca = X509::from_pem(issued.issuer_chain_pem[0].as_bytes()).unwrap();
        assert!(leaf.verify(&ca.public_key().unwrap()).unwrap());

        a.revoke("default", "acme", &issued.serial_hex, None, "", "")
            .unwrap();
        let again = a
            .revoke("default", "acme", &issued.serial_hex, None, "", "")
            .unwrap();
        assert!(again.already);
        let crl = a.build_crl("default", "acme").unwrap();
        assert_eq!(crl.count, 1);
        let parsed = X509Crl::from_der(&crl.der).unwrap();
        assert!(parsed.verify(&ca.public_key().unwrap()).unwrap());
        let refused = a.release("default", "acme", &issued.serial_hex);
        assert_eq!(refused.unwrap_err().code, codes::STS_PKI_0059);

        // A rebuilt branch supersedes the Intermediate it replaced.
        let old = a.raw_row_for("acme").unwrap()["intermediate"].clone();
        a.build_scope("acme", &BuildOptions::default()).unwrap();
        assert!(a
            .is_revoked(SERVICE_SCOPE, "root", str_of(&old, "serialHex"))
            .is_some());
        assert!(a.scope_chains_to_root("acme"));
    }

    #[test]
    fn the_refusals_are_nodes() {
        let a = authority();
        let r = a.algorithms_from(Some("rsa-1024"), None, None).unwrap_err();
        assert_eq!(r.code, codes::STS_PKI_0002);
        let r = a
            .algorithms_from(Some("ec-p256"), Some("sha256-rsa"), None)
            .unwrap_err();
        assert_eq!(r.code, codes::STS_PKI_0004);
        let r = a.algorithms_from(None, None, Some("ec-p256")).unwrap_err();
        assert_eq!(r.code, codes::STS_PKI_0200);
        let mut product = PkiConfig::development();
        product.uses_broken_algorithms = false;
        a.set_config(product);
        let r = a.algorithms_from(None, Some("sha1-rsa"), None).unwrap_err();
        assert_eq!(r.code, codes::STS_PKI_0191);
        let r = a
            .issue_under("default", "nope", &LeafSpec::default())
            .unwrap_err();
        assert_eq!(r.code, codes::STS_PKI_0022);
    }
}
