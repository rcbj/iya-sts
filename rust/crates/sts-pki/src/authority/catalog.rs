// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shape of the hierarchy as `common/pki.js` declares it: `TIERS`,
//! `SERVICE_SCOPE` and `PROCESS_SCOPE`, `USE_CASES` with their scopes,
//! common names and the two that differ (`spiffe`'s `pathLen` and key
//! algorithm, `cell`'s `multiCellOnly`), and the rules computed from them —
//! `useCasesFor()`, `intermediatePathLen()`, `issuingPathLen()`,
//! `scopeKindOf()`, `primaryUseCaseFor()` — and the key algorithms an
//! authority may hold (`crypto_impl/key_material.js`'s table), each made
//! here as Node makes it.

use openssl::pkey::{PKey, Private};
use sts_crypto::pq_x509::{self, Family, Use};

use crate::error::{PkiError, PkiResult};
use crate::x509::algorithms;

/// The service's own row, which holds the Root (`SERVICE_SCOPE`).
pub const SERVICE_SCOPE: &str = "*service";
/// The process branch (`PROCESS_SCOPE`).
pub const PROCESS_SCOPE: &str = "*process";
/// The default realm's id (`realms.DEFAULT_ID`).
pub const DEFAULT_REALM: &str = "default";
/// `DEFAULT_KEY_ALG`.
pub const DEFAULT_KEY_ALG: &str = "rsa-2048";
/// `DEFAULT_SIG_ALG`.
pub const DEFAULT_SIG_ALG: &str = "sha256-rsa";
/// `DEFAULT_ORGANISATION` (#1294).
pub const DEFAULT_ORGANISATION: &str = "iya-sts";

/// One of `TIERS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    pub id: &'static str,
    pub order: u8,
    pub profile: &'static str,
    pub label: &'static str,
}

/// `TIERS`, Root first.
pub const TIERS: [Tier; 3] = [
    Tier {
        id: "root",
        order: 0,
        profile: "root-ca",
        label: "Root CA",
    },
    Tier {
        id: "intermediate",
        order: 1,
        profile: "intermediate-ca",
        label: "Intermediate CA",
    },
    Tier {
        id: "issuing",
        order: 2,
        profile: "issuing-ca",
        label: "Issuing CA",
    },
];

/// Which kind of Intermediate signs a use case's Issuing CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// A realm's own Intermediate.
    Realm,
    /// The process branch.
    Process,
}

/// One of `USE_CASES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UseCase {
    pub id: &'static str,
    pub scope: ScopeKind,
    pub label: &'static str,
    /// The common name's middle: `<organisation> <cn> (<scope>)`.
    pub cn: &'static str,
    /// Built only in a service deployed as cells (`cell`).
    pub multi_cell_only: bool,
    /// The Issuing CA's own pathLen (`spiffe` is 1, the rest 0).
    pub path_len: i64,
    /// A PREFERENCE (`algorithmsForUseCase()`): `spiffe`'s EC P-256.
    pub key_alg: Option<&'static str>,
    pub signature_alg: Option<&'static str>,
}

const fn uc(
    id: &'static str,
    scope: ScopeKind,
    label: &'static str,
    cn: &'static str,
) -> UseCase {
    UseCase {
        id,
        scope,
        label,
        cn,
        multi_cell_only: false,
        path_len: 0,
        key_alg: None,
        signature_alg: None,
    }
}

/// `USE_CASES`, in Node's order (the order a branch builds them in, and
/// the order a page lists them).
pub const USE_CASES: [UseCase; 15] = [
    uc("jose", ScopeKind::Realm, "JOSE signing", "JOSE Signing CA"),
    uc("xml", ScopeKind::Realm, "XML signing", "XML Signing CA"),
    uc(
        "assertions",
        ScopeKind::Realm,
        "Application assertions",
        "Application Assertion CA",
    ),
    uc("tls", ScopeKind::Process, "TLS listeners", "TLS Issuing CA"),
    UseCase {
        multi_cell_only: true,
        ..uc(
            "cell",
            ScopeKind::Process,
            "Inter-cell channel",
            "Inter-cell Issuing CA",
        )
    },
    UseCase {
        path_len: 1,
        key_alg: Some("ec-p256"),
        signature_alg: Some("sha256-ecdsa"),
        ..uc(
            "spiffe",
            ScopeKind::Realm,
            "SPIFFE authority",
            "SPIFFE Issuing CA",
        )
    },
    uc(
        "pep-tls",
        ScopeKind::Realm,
        "Remote PEP listeners",
        "Remote PEP TLS Issuing CA",
    ),
    uc(
        "realm-tls",
        ScopeKind::Realm,
        "Custom listeners",
        "Realm Listener TLS Issuing CA",
    ),
    uc(
        "kdc",
        ScopeKind::Realm,
        "Kerberos KDC (PKINIT)",
        "Kerberos KDC Issuing CA",
    ),
    uc(
        "acme",
        ScopeKind::Realm,
        "ACME enrollment",
        "ACME Issuing CA",
    ),
    uc("est", ScopeKind::Realm, "EST enrollment", "EST Issuing CA"),
    uc(
        "scep",
        ScopeKind::Realm,
        "SCEP enrollment",
        "SCEP Issuing CA",
    ),
    uc(
        "tls-client",
        ScopeKind::Realm,
        "TLS client certificates",
        "TLS Client Issuing CA",
    ),
    uc(
        "message-signing",
        ScopeKind::Realm,
        "Message signing",
        "Message Signing Issuing CA",
    ),
    uc(
        "policy-signing",
        ScopeKind::Realm,
        "Policy export signing",
        "Policy Export Signing CA",
    ),
];

/// `useCase()`: one use case by id.
#[tracing::instrument(level = "debug")]
pub fn use_case(id: &str) -> Option<&'static UseCase> {
    USE_CASES.iter().find(|one| one.id == id)
}

/// `useCasesFor()`: the use cases an Intermediate of one kind carries —
/// `cell` only where the service is deployed as cells.
#[tracing::instrument(level = "debug")]
pub fn use_cases_for(
    kind: ScopeKind,
    multi_cell: bool,
) -> Vec<&'static UseCase> {
    USE_CASES
        .iter()
        .filter(|one| one.scope == kind && (!one.multi_cell_only || multi_cell))
        .collect()
}

/// `intermediatePathLen()`: one deeper than the deepest Issuing CA it
/// carries — 2 for a realm (SPIFFE's downstream CA), 1 for the process.
#[tracing::instrument(level = "debug")]
pub fn intermediate_path_len(kind: ScopeKind, multi_cell: bool) -> i64 {
    1 + use_cases_for(kind, multi_cell)
        .iter()
        .map(|one| one.path_len)
        .max()
        .unwrap_or(0)
}

/// `issuingPathLen()`.
#[tracing::instrument(level = "debug")]
pub fn issuing_path_len(id: &str) -> i64 {
    use_case(id).map_or(0, |one| one.path_len)
}

/// `scopeKindOf()`.
#[tracing::instrument(level = "debug")]
pub fn scope_kind_of(scope: &str) -> ScopeKind {
    if scope == PROCESS_SCOPE {
        ScopeKind::Process
    } else {
        ScopeKind::Realm
    }
}

/// `primaryUseCaseFor()`: what `rawChainFor()` puts third.
#[tracing::instrument(level = "debug")]
pub fn primary_use_case_for(scope: &str) -> &'static str {
    match scope_kind_of(scope) {
        ScopeKind::Process => "tls",
        ScopeKind::Realm => "assertions",
    }
}

/// `realmIdOf()` for a scope a caller names: `''` is the default realm.
#[tracing::instrument(level = "debug")]
pub fn scope_id(scope: &str) -> String {
    if scope.is_empty() {
        DEFAULT_REALM.to_string()
    } else {
        scope.to_string()
    }
}

/// `scopeSegment()`: a scope as a URL names it.
#[tracing::instrument(level = "debug")]
pub fn scope_segment(scope: &str) -> String {
    match scope {
        SERVICE_SCOPE => "service".to_string(),
        PROCESS_SCOPE => "process".to_string(),
        "" => DEFAULT_REALM.to_string(),
        other => other.to_string(),
    }
}

/// `scopeFromSegment()`, with `default` the default realm's row (Node
/// reads `''` as the ambient realm, which on the revocation listener is
/// the default one).
#[tracing::instrument(level = "debug")]
pub fn scope_from_segment(segment: &str) -> String {
    match segment {
        "service" => SERVICE_SCOPE.to_string(),
        "process" => PROCESS_SCOPE.to_string(),
        "" => DEFAULT_REALM.to_string(),
        other => other.to_string(),
    }
}

/// One of `key_material.js`'s key algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAlg {
    /// The id, lower case (`rsa-2048`, `ec-p256`, `ml-dsa-65`).
    pub id: String,
    /// `rsa`, `ec`, `okp` or `pqc`.
    pub kind: &'static str,
    pub bits: u32,
    /// `P-256`, `P-384`, `P-521` for `ec`.
    pub curve: Option<&'static str>,
    /// The post-quantum id (`ML-DSA-65`) for `pqc`.
    pub pqc: Option<&'static str>,
    pub label: String,
}

impl KeyAlg {
    /// Whether a key of this algorithm can sign.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signs(&self) -> bool {
        match self.pqc {
            Some(id) => pq_x509::alg(id).is_some_and(|a| a.usage == Use::Sig),
            None => true,
        }
    }

    /// `x509.signatureAlgorithmsFor(desc)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signature_algorithms(&self) -> Vec<String> {
        algorithms::signature_algorithms_for(self.kind, self.pqc)
    }

    /// `x509.defaultSignatureAlgorithm(desc)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn default_signature_algorithm(&self) -> String {
        algorithms::default_signature_algorithm(self.kind, self.curve, self.pqc)
    }

    /// `generateKeyPair()`: `(private PKCS#8 PEM, public SPKI PEM)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn generate(&self) -> PkiResult<(String, String)> {
        if let Some(id) = self.pqc {
            let (public, private) = pq_x509::generate_key_pair(id)?;
            return Ok((
                pq_x509::private_pem(id, &private, None)?,
                pq_x509::public_pem(id, &public)?,
            ));
        }
        let key: PKey<Private> = match self.kind {
            "rsa" => PKey::from_rsa(openssl::rsa::Rsa::generate(self.bits)?)?,
            "okp" => PKey::generate_ed25519()?,
            _ => {
                let nid = match self.curve {
                    Some("P-384") => openssl::nid::Nid::SECP384R1,
                    Some("P-521") => openssl::nid::Nid::SECP521R1,
                    _ => openssl::nid::Nid::X9_62_PRIME256V1,
                };
                let group = openssl::ec::EcGroup::from_curve_name(nid)?;
                PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?
            }
        };
        let private = String::from_utf8(key.private_key_to_pem_pkcs8()?)
            .map_err(|e| PkiError::new(e.to_string()))?;
        let public = String::from_utf8(key.public_key_to_pem()?)
            .map_err(|e| PkiError::new(e.to_string()))?;
        Ok((private, public))
    }
}

/// `keyAlgIds()`: the classical seven, then the post-quantum families in
/// `ML-DSA`, `SLH-DSA`, composite, `ML-KEM` order.
#[tracing::instrument(level = "debug")]
pub fn key_alg_ids() -> Vec<String> {
    let mut out: Vec<String> = [
        "rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384", "ec-p521",
        "ed25519",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for family in [
        Family::MlDsa,
        Family::SlhDsa,
        Family::Composite,
        Family::MlKem,
    ] {
        for a in pq_x509::algs().iter().filter(|a| a.family == family) {
            out.push(a.id.to_lowercase());
        }
    }
    out
}

/// `keyMaterial.keyAlg(id)`: the descriptor, any case, or `None`.
#[tracing::instrument(level = "debug")]
pub fn key_alg(id: &str) -> Option<KeyAlg> {
    let wanted = id.to_ascii_lowercase();
    let classical = |kind, bits, curve, label: &str| KeyAlg {
        id: wanted.clone(),
        kind,
        bits,
        curve,
        pqc: None,
        label: label.to_string(),
    };
    Some(match wanted.as_str() {
        "rsa-2048" => classical("rsa", 2048, None, "RSA 2048"),
        "rsa-3072" => classical("rsa", 3072, None, "RSA 3072"),
        "rsa-4096" => classical("rsa", 4096, None, "RSA 4096"),
        "ec-p256" => classical("ec", 0, Some("P-256"), "ECDSA P-256"),
        "ec-p384" => classical("ec", 0, Some("P-384"), "ECDSA P-384"),
        "ec-p521" => classical("ec", 0, Some("P-521"), "ECDSA P-521"),
        "ed25519" => classical("okp", 0, None, "Ed25519 (EdDSA)"),
        _ => {
            let a = pq_x509::algs()
                .iter()
                .find(|a| a.id.eq_ignore_ascii_case(&wanted))?;
            KeyAlg {
                id: wanted.clone(),
                kind: "pqc",
                bits: 0,
                curve: None,
                pqc: Some(a.id),
                label: pq_x509::label_for(a.id),
            }
        }
    })
}

/// `alternativeKeyAlgs()`: the pure ML-DSA and SLH-DSA signature keys.
#[tracing::instrument(level = "debug")]
pub fn alternative_key_algs() -> Vec<String> {
    pq_x509::algs()
        .iter()
        .filter(|a| {
            a.usage == Use::Sig
                && matches!(a.family, Family::MlDsa | Family::SlhDsa)
        })
        .map(|a| a.id.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_realm_intermediate_is_two_deep_and_the_process_one() {
        assert_eq!(intermediate_path_len(ScopeKind::Realm, false), 2);
        assert_eq!(intermediate_path_len(ScopeKind::Process, true), 1);
        let process: Vec<&str> = use_cases_for(ScopeKind::Process, false)
            .iter()
            .map(|u| u.id)
            .collect();
        assert_eq!(process, vec!["tls"]);
        assert_eq!(use_cases_for(ScopeKind::Realm, false).len(), 13);
    }

    #[test]
    fn segments_round_trip() {
        for scope in [SERVICE_SCOPE, PROCESS_SCOPE, "default", "acme"] {
            assert_eq!(scope_from_segment(&scope_segment(scope)), scope);
        }
    }
}
