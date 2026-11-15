// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What `common/pki.js` and `common/pki_revocation.js` read from
//! `config.js` and `mode.js`, read ONCE per call into a plain value so the
//! authority can be driven by a test without a settings tree:
//! `pki.keyAlgorithm` (and whether it is only the default),
//! `pki.signatureAlgorithm` as `mode.valueInForce()` gives it,
//! `pki.alternativeKeyAlgorithm`, `pki.organisation`, the three
//! `pki.*LifetimeYears`, `pki.leafLifetimeDays`, `pki.crlLifetimeMinutes`,
//! the addresses `distributionPoints()` builds from, whether the service
//! runs as cells, and the two mode questions (`usesBrokenAlgorithms()`,
//! `defaultRsaBits()`).

use std::collections::BTreeMap;

use sts_core::mode::Mode;
use sts_core::settings::{Settings, Source};

/// The addresses a certificate names for its issuer's CRL, OCSP responder
/// and certificate (`httpBase()`, `ldapHost()`, `publishedPort()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    /// `pki.distributionBaseUrl`, trailing slashes dropped; empty for none.
    pub base_url: String,
    /// `tls.hostnames[0]`, else `localhost`.
    pub host: String,
    /// `pki.httpPort`: the plain revocation listener, 0 for none.
    pub http_port: i64,
    /// `pki.distributionPort`: the port a certificate names, 0 for the
    /// listener's own.
    pub distribution_port: i64,
    /// `global.https` and `global.port`, for a service with no plain
    /// listener.
    pub https: bool,
    pub port: i64,
    /// `pki.distributionLdapHost`, empty for the first hostname.
    pub ldap_host: String,
    /// `pki.distributionLdapPort`, 0 for `ldap.port`.
    pub ldap_distribution_port: i64,
    pub ldap_port: i64,
    /// The default realm's base DN (`realms.baseDnOf('default')`), and the
    /// service's DNS domain, for a realm's own (`baseDnOfDomain()`).
    pub default_base_dn: String,
    pub domain: String,
    /// Each realm's own base DN (`realms.baseDnOf(id)`), where known.
    pub realm_base_dns: BTreeMap<String, String>,
}

impl Distribution {
    /// `httpBase()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn http_base(&self) -> String {
        let set = self.base_url.trim();
        if !set.is_empty() {
            return set.trim_end_matches('/').to_string();
        }
        let published = |named: i64, listener: i64| {
            if named > 0 {
                named
            } else {
                listener
            }
        };
        if self.http_port > 0 {
            return format!(
                "http://{}:{}",
                self.host,
                published(self.distribution_port, self.http_port)
            );
        }
        format!(
            "{}://{}:{}",
            if self.https { "https" } else { "http" },
            self.host,
            published(self.distribution_port, self.port)
        )
    }

    /// `ldapHost()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ldap_host(&self) -> String {
        let set = self.ldap_host.trim();
        if set.is_empty() {
            self.host.clone()
        } else {
            set.to_string()
        }
    }

    /// `directoryBaseFor()`: where a scope's CRLs live in the directory —
    /// the default realm's tree for the service, the process and the
    /// default realm, a realm's own otherwise.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn directory_base_for(&self, scope: &str) -> String {
        use super::catalog::{DEFAULT_REALM, PROCESS_SCOPE, SERVICE_SCOPE};
        if scope == SERVICE_SCOPE
            || scope == PROCESS_SCOPE
            || scope.is_empty()
            || scope == DEFAULT_REALM
        {
            return self.default_base_dn.clone();
        }
        self.realm_base_dns.get(scope).cloned().unwrap_or_else(|| {
            base_dn_of_domain(&format!("{}.{}", scope, self.domain))
        })
    }

    /// The LDAP port a CRL address names.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ldap_port(&self) -> i64 {
        if self.ldap_distribution_port > 0 {
            self.ldap_distribution_port
        } else {
            self.ldap_port
        }
    }
}

/// The settings the authority reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiConfig {
    /// `pki.keyAlgorithm`.
    pub key_algorithm: String,
    /// Whether `pki.keyAlgorithm` came from a default layer (`sourceOf()`
    /// begins `default`), which lets `spiffe` keep its EC P-256.
    pub key_algorithm_defaulted: bool,
    /// `mode.valueInForce('pki.signatureAlgorithm')`.
    pub signature_algorithm: String,
    /// `pki.alternativeKeyAlgorithm`, `none` for a classical authority.
    pub alternative_key_algorithm: String,
    /// `pki.organisation`.
    pub organisation: String,
    pub root_years: i64,
    pub intermediate_years: i64,
    pub issuing_years: i64,
    /// `pki.leafLifetimeDays`.
    pub leaf_days: i64,
    /// `pki.crlLifetimeMinutes`.
    pub crl_lifetime_minutes: i64,
    /// `pki.autoBuild`.
    pub auto_build: bool,
    /// `cells.isMulti()`: `cells.id` is set.
    pub multi_cell: bool,
    /// `mode.usesBrokenAlgorithms()`: SHA-1 signatures are development's.
    pub uses_broken_algorithms: bool,
    /// `mode.defaultRsaBits()`.
    pub default_rsa_bits: i64,
    pub distribution: Distribution,
}

impl PkiConfig {
    /// The values a test starts from: Node's defaults in development mode.
    #[tracing::instrument(level = "debug")]
    pub fn development() -> PkiConfig {
        PkiConfig {
            key_algorithm: String::new(),
            key_algorithm_defaulted: true,
            signature_algorithm: String::new(),
            alternative_key_algorithm: "none".to_string(),
            organisation: String::new(),
            root_years: 0,
            intermediate_years: 0,
            issuing_years: 0,
            leaf_days: 365,
            crl_lifetime_minutes: 60,
            auto_build: true,
            multi_cell: false,
            uses_broken_algorithms: true,
            default_rsa_bits: 2048,
            distribution: Distribution {
                base_url: String::new(),
                host: "localhost".to_string(),
                http_port: 8080,
                distribution_port: 0,
                https: true,
                port: 8081,
                ldap_host: String::new(),
                ldap_distribution_port: 0,
                ldap_port: 389,
                default_base_dn: "dc=example,dc=com".to_string(),
                domain: "example.com".to_string(),
                realm_base_dns: BTreeMap::new(),
            },
        }
    }

    /// Read from the settings and the mode, as `config.value()` answers.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_settings(settings: &Settings, mode: &Mode) -> PkiConfig {
        let text = |k: &str| settings.value_of(k).as_str().to_string();
        let int = |k: &str| settings.value_of(k).as_int();
        let hosts = settings.value_of("tls.hostnames");
        let host = hosts
            .as_list()
            .first()
            .filter(|h| !h.is_empty())
            .cloned()
            .unwrap_or_else(|| "localhost".to_string());
        let domain = text("global.domain");
        let defaulted = matches!(
            settings.source_named("pki.keyAlgorithm"),
            Source::Default | Source::Defaults
        );
        PkiConfig {
            key_algorithm: text("pki.keyAlgorithm"),
            key_algorithm_defaulted: defaulted,
            signature_algorithm: mode
                .value_in_force("pki.signatureAlgorithm")
                .as_str()
                .trim()
                .to_string(),
            alternative_key_algorithm: text("pki.alternativeKeyAlgorithm"),
            organisation: text("pki.organisation"),
            root_years: int("pki.rootLifetimeYears"),
            intermediate_years: int("pki.intermediateLifetimeYears"),
            issuing_years: int("pki.issuingLifetimeYears"),
            leaf_days: int("pki.leafLifetimeDays"),
            crl_lifetime_minutes: int("pki.crlLifetimeMinutes"),
            auto_build: settings.value_of("pki.autoBuild").as_bool(),
            multi_cell: !text("cells.id").trim().is_empty(),
            uses_broken_algorithms: mode
                .predicate("usesBrokenAlgorithms")
                .unwrap_or(false),
            default_rsa_bits: mode.default_rsa_bits(),
            distribution: Distribution {
                base_url: text("pki.distributionBaseUrl"),
                host,
                http_port: int("pki.httpPort"),
                distribution_port: int("pki.distributionPort"),
                https: settings.value_of("global.https").as_bool(),
                port: int("global.port"),
                ldap_host: text("pki.distributionLdapHost"),
                ldap_distribution_port: int("pki.distributionLdapPort"),
                ldap_port: int("ldap.port"),
                default_base_dn: base_dn_of_domain(&domain),
                domain,
                realm_base_dns: BTreeMap::new(),
            },
        }
    }

    /// `leafLifetimeDays()`: 365 when unset.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn leaf_lifetime_days(&self) -> i64 {
        if self.leaf_days > 0 {
            self.leaf_days
        } else {
            365
        }
    }

    /// `crlLifetimeMs()`: at least a minute, an hour when unset.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn crl_lifetime_ms(&self) -> i64 {
        self.crl_lifetime_minutes.max(1) * 60_000
    }

    /// `configuredTierYears()`: the setting, 0 for the profile's default.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn tier_years(&self, tier: &str) -> i64 {
        let n = match tier {
            "root" => self.root_years,
            "intermediate" => self.intermediate_years,
            "issuing" => self.issuing_years,
            _ => 0,
        };
        n.max(0)
    }

    /// The organisation a build uses when none was asked for.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn organisation_or_default(&self) -> String {
        if self.organisation.is_empty() {
            super::catalog::DEFAULT_ORGANISATION.to_string()
        } else {
            self.organisation.clone()
        }
    }
}

/// `realms.baseDnOfDomain()`: `example.com` is `dc=example,dc=com`.
#[tracing::instrument(level = "debug")]
pub fn base_dn_of_domain(domain: &str) -> String {
    domain
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| format!("dc={}", p))
        .collect::<Vec<_>>()
        .join(",")
}
