// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The listener certificate as `tls/tls_server.js` settles it at start,
//! read from the settings: a supplied pair (`tls.certificateFile`,
//! `tls.keyFile`), or the self-signed bootstrap over a key made now —
//! one per algorithm `tls.certificateAlgorithms` names — certified under
//! the process branch's TLS Issuing CA where `pki.autoBuild` is on
//! (`certifyServerCertificateUnderPki()`, `takeIssuedCertificate()`).
//!
//! THE HIERARCHY IS BUILT FOR THIS RUN. Node's development mode does the
//! same at every start; a product install keeps its Root and process
//! branch in the keystore, and reading them is phase 6's
//! (`sts-pki::listener`'s module comment). The runtime says which it did.

use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use sts_core::settings::Settings;
use sts_pki::listener::{
    bootstrap, supplied, BranchOptions, DistributionPoints,
    ListenerCertificate, ListenerIdentity, ProcessBranch,
};

/// What the listeners present, and the Root they chain to.
pub struct ListenerMaterial {
    /// Every certificate, the first the RSA one (LDAPS serves the first).
    pub certificates: Vec<ListenerCertificate>,
    /// The process branch, where one was built.
    pub branch: Option<ProcessBranch>,
    pub identity: ListenerIdentity,
}

impl ListenerMaterial {
    /// The service Root, for the client truststore's issued anchor.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn root_pem(&self) -> Option<String> {
        self.branch.as_ref().map(|b| b.root_pem().to_string())
    }

    /// `certificateProvenance()`'s phrase.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn provenance(&self) -> &'static str {
        match self.certificates.first().map(|c| c.provenance) {
            Some(sts_pki::listener::Provenance::Supplied) => {
                "issued by somebody else and read from disk at startup (tls.certificateFile), so it does \
                 NOT change when this service restarts — trust its issuer once"
            }
            Some(sts_pki::listener::Provenance::Issued) => {
                "issued by this service's TLS Issuing CA under its own Root, over a key each node keeps \
                 where minted state persists and makes at every start where it does not, so trust the \
                 Root (/pki/revocation lists it) rather than the certificate itself"
            }
            _ => "self-signed and regenerated on every start",
        }
    }
}

/// Why the material could not be made: fatal at start.
pub struct MaterialProblem {
    pub code: ErrorCode,
    pub message: String,
}

fn text(settings: &Settings, key: &str) -> String {
    settings.value_of(key).as_str().trim().to_string()
}

fn int(settings: &Settings, key: &str) -> i64 {
    settings.value_of(key).as_int()
}

/// The identity a listener certificate is made for.
#[tracing::instrument(level = "debug", skip_all)]
pub fn identity(settings: &Settings) -> ListenerIdentity {
    let hostnames = settings.value_of("tls.hostnames").as_list().to_vec();
    let bits = int(settings, "tls.selfSignedKeyBits");
    ListenerIdentity {
        hostnames: if hostnames.is_empty() {
            vec!["localhost".to_string()]
        } else {
            hostnames
        },
        ips: settings.value_of("tls.ips").as_list().to_vec(),
        organisation: {
            let o = text(settings, "tls.selfSignedOrganization");
            if o.is_empty() {
                "iya-sts".to_string()
            } else {
                o
            }
        },
        rsa_bits: u32::try_from(bits)
            .ok()
            .filter(|b| *b >= 2048)
            .unwrap_or(2048),
        self_signed_years: i32::try_from(int(
            settings,
            "tls.selfSignedValidityYears",
        ))
        .ok()
        .filter(|y| *y > 0)
        .unwrap_or(2),
    }
}

/// `pki_revocation.js`'s `httpBase()` and the ldap half of
/// `distributionPoints()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn distribution_points(settings: &Settings) -> DistributionPoints {
    let host = settings
        .value_of("tls.hostnames")
        .as_list()
        .first()
        .cloned()
        .unwrap_or_else(|| "localhost".to_string());
    let published = |set: &str, listener: &str| {
        let named = int(settings, set);
        if named > 0 {
            named
        } else {
            int(settings, listener)
        }
    };
    let base = text(settings, "pki.distributionBaseUrl");
    let http_base = if !base.is_empty() {
        base.trim_end_matches('/').to_string()
    } else if int(settings, "pki.httpPort") > 0 {
        format!(
            "http://{}:{}",
            host,
            published("pki.distributionPort", "pki.httpPort")
        )
    } else {
        format!(
            "{}://{}:{}",
            if settings.value_of("global.https").as_bool() {
                "https"
            } else {
                "http"
            },
            host,
            published("pki.distributionPort", "global.port")
        )
    };
    let ldap_host = {
        let set = text(settings, "pki.distributionLdapHost");
        if set.is_empty() {
            host.clone()
        } else {
            set
        }
    };
    DistributionPoints {
        http_base,
        ldap_base: format!(
            "ldap://{}:{}",
            ldap_host,
            published("pki.distributionLdapPort", "ldap.port")
        ),
        directory_base: sts_core::realm::base_dn_of_domain(
            settings.value_of("global.domain").as_str(),
        ),
    }
}

/// The algorithms `tls.certificateAlgorithms` names, RSA first; an unknown
/// one is skipped with a warning, and none at all is RSA alone.
fn algorithms(settings: &Settings) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in settings.value_of("tls.certificateAlgorithms").as_list() {
        let a = a.trim().to_ascii_lowercase();
        if ["rsa", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"].contains(&a.as_str())
        {
            if !out.contains(&a) {
                out.push(a);
            }
        } else {
            tracing::warn!(
                "tls: tls.certificateAlgorithms names \"{}\", which is not rsa, ml-dsa-44, ml-dsa-65 or \
                 ml-dsa-87; it is skipped.",
                a
            );
        }
    }
    if out.is_empty() {
        out.push("rsa".to_string());
    }
    out.sort_by_key(|a| a != "rsa");
    out
}

/// The listener material, as `tls_server.js` settles it before anything
/// binds.
#[tracing::instrument(level = "debug", skip_all)]
pub fn settle(
    settings: &Settings,
) -> Result<ListenerMaterial, MaterialProblem> {
    let identity = identity(settings);
    let cert_file = text(settings, "tls.certificateFile");
    let key_file = text(settings, "tls.keyFile");
    if !cert_file.is_empty() || !key_file.is_empty() {
        if cert_file.is_empty() || key_file.is_empty() {
            return Err(MaterialProblem {
                code: codes::STS_TLS_0002,
                message: format!(
                    "tls.certificateFile and tls.keyFile go together: {} is not set. Set both, or neither \
                     to keep the self-signed certificate this service issues at startup.",
                    if cert_file.is_empty() {
                        "tls.certificateFile"
                    } else {
                        "tls.keyFile"
                    }
                ),
            });
        }
        let read = |f: &str| std::fs::read_to_string(f);
        let (cert_text, key_text) = match (read(&cert_file), read(&key_file)) {
            (Ok(c), Ok(k)) => (c, k),
            (Err(e), _) | (_, Err(e)) => {
                return Err(MaterialProblem {
                    code: codes::STS_TLS_0003,
                    message: format!(
                        "tls: cannot read the certificate or key named by tls.certificateFile / \
                         tls.keyFile: {}",
                        e
                    ),
                })
            }
        };
        let one = supplied(&cert_file, &cert_text, &key_file, &key_text)
            .map_err(|p| MaterialProblem {
                code: p.code,
                message: format!("tls: {}", p.message),
            })?;
        if !settings
            .value_of("tls.certificateAlgorithms")
            .as_list()
            .is_empty()
            && algorithms(settings) != vec!["rsa".to_string()]
        {
            tracing::info!(
                "tls: tls.certificateAlgorithms is ignored while tls.certificateFile is set: it chooses among \
                 certificates this service issues."
            );
        }
        return Ok(ListenerMaterial {
            certificates: vec![one],
            branch: None,
            identity,
        });
    }
    let fail = |e: sts_pki::PkiError| MaterialProblem {
        code: codes::STS_TLS_0009,
        message: format!(
            "tls: the listener certificate could not be made: {}",
            e
        ),
    };
    let mut bootstraps = Vec::new();
    for a in algorithms(settings) {
        bootstraps.push(bootstrap(&identity, &a).map_err(fail)?);
    }
    if !settings.value_of("pki.autoBuild").as_bool() {
        return Ok(ListenerMaterial {
            certificates: bootstraps,
            branch: None,
            identity,
        });
    }
    let options = BranchOptions {
        organisation: {
            let o = text(settings, "pki.organisation");
            if o.is_empty() {
                "iya-sts".to_string()
            } else {
                o
            }
        },
        key_algorithm: text(settings, "pki.keyAlgorithm"),
        root_years: i32::try_from(int(settings, "pki.rootLifetimeYears"))
            .unwrap_or(0),
        intermediate_years: i32::try_from(int(
            settings,
            "pki.intermediateLifetimeYears",
        ))
        .unwrap_or(0),
        issuing_years: i32::try_from(int(settings, "pki.issuingLifetimeYears"))
            .unwrap_or(0),
        points: distribution_points(settings),
    };
    let (branch, fell_back) = ProcessBranch::build(&options).map_err(fail)?;
    if fell_back {
        tracing::warn!(
            "{}pki: pki.keyAlgorithm names a composite ML-DSA key ({}), which the TLS listeners cannot load, so \
             the service Root and the process branch were built with the classical default instead.",
            tag(codes::STS_PKI_0273),
            options.key_algorithm
        );
    }
    let days = int(settings, "pki.leafLifetimeDays").max(1);
    let mut certificates = Vec::new();
    for b in &bootstraps {
        certificates.push(branch.certify(b, &identity, days).map_err(fail)?);
    }
    tracing::info!(
        "tls: the listener certificate is a leaf of the TLS Issuing CA under a service Root built for this \
         run (the stored hierarchy of a product install is read in phase 6)."
    );
    Ok(ListenerMaterial {
        certificates,
        branch: Some(branch),
        identity,
    })
}
