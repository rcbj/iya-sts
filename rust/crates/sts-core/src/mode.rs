// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one place `development` and `product` are told apart. A port of
//! `common/mode.js`, whose comments argue each predicate (rust/DESIGN.md
//! section 4.4).
//!
//! **A behaviour that differs between the modes is a PREDICATE at the call
//! site, named for the QUESTION** — `mode.verifies_credentials()` says why a
//! branch exists where "is this product?" says only when. So the mode itself
//! is private to this module: a family asks a predicate, and the day one
//! wants a setting of its own (as `embeds_protocol_debugger` has) or a third
//! mode arrives, no call site moves.
//!
//! **Every predicate reads the AMBIENT realm's `global.mode`**, through
//! [`Settings`], never cached — the mode is runtime-settable and per realm.
//!
//! The predicates' NAMES are `mode.js`'s, exported to `tables/mode.json`
//! with the two tables `/admin/mode` draws; a test here fails on a name this
//! module does not answer, so a predicate added to the Node module and not
//! here is caught before the cutover.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use serde_json::{json, Value as Json};

use crate::errors::codes;
use crate::log::tag;
use crate::settings::{
    js_string, js_trim, keys, row, rows, DefaultValue, Key, Refusal,
    SettingRow, SettingValue, Settings,
};

/// `global.mode`'s two values.
pub const DEVELOPMENT: &str = "development";
pub const PRODUCT: &str = "product";

/// The export of `mode.js`'s tables.
static TABLE: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../tables/mode.json"))
        .unwrap_or(Json::Null)
});

/// Defines the predicates that are the mode, or the mode and one boolean
/// setting: `product` answers true in product mode, `development` in
/// development mode; `product_unless(KEY)` is product unless an operator
/// turned KEY on (an opt-out), `development_or(KEY)` development or KEY on
/// (an opt-in), and `product_and(KEY)` product with KEY on. Each reads its
/// setting as `config.value(KEY) === true`: only a boolean `true` counts.
/// Each also answers to its `mode.js` name through [`Mode::answer`], which
/// is how a settings row's `onlyWhile` marker names one.
macro_rules! predicates {
    ($($method:ident = $name:literal, $when:ident $(($key:ident))?;)*) => {
        impl Mode {
            $(
                #[doc = concat!("`", $name, "` in `common/mode.js`.")]
                pub fn $method(&self) -> bool {
                    predicates!(@answer self, $when $(, $key)?)
                }
            )*

            fn simple_predicate(&self, name: &str) -> Option<bool> {
                match name {
                    $($name => Some(self.$method()),)*
                    _ => None,
                }
            }
        }
    };
    (@answer $self:ident, product) => { $self.is_product() };
    (@answer $self:ident, development) => { !$self.is_product() };
    (@answer $self:ident, product_unless, $key:ident) => {
        $self.is_product() && !$self.is_on(keys::$key)
    };
    (@answer $self:ident, development_or, $key:ident) => {
        !$self.is_product() || $self.is_on(keys::$key)
    };
    (@answer $self:ident, product_and, $key:ident) => {
        $self.is_product() && $self.is_on(keys::$key)
    };
}

/// What `oauth-oidc/oauth2_bcp.js`'s `waivers()` answers: the rows of RFC
/// 9700 an administrator waived in the ambient realm (#1295), as data. The
/// report carries them on its `oauth-security-bcp` row. Node requires that
/// module LAZILY from `report()`; `sts-core` cannot depend on the crate
/// that will own it, so it is a slot, filled by the OAuth crate when
/// `oauth2_bcp` is ported — and EMPTY until then, which answers no waiver.
pub trait OAuthBcpWaivers: Send + Sync {
    fn waivers(&self) -> Vec<Json>;
}

/// A signing key `pki.pinnedSigners` off would demote (#263): what
/// `pki.js`'s `pinsBlockingSignersOff()` lists.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockingPin {
    pub unit: String,
    pub kid: String,
    pub realm: String,
    /// `active` (signing) or anything else (published, not yet signing).
    pub role: String,
}

/// The certificate authority's half of the pinned-signer rule. Node reads
/// `pki.js` out of `require.cache` — a process that never loaded the
/// certificate authority holds no pin to protect — so here it is a slot,
/// and an EMPTY slot refuses nothing, as that process does.
pub trait PinnedSigners: Send + Sync {
    /// The pins blocking `pki.pinnedSigners` off in `realm`; `process` is
    /// true where no realm is ambient (the write lands process-wide).
    fn blocking_signers_off(
        &self,
        realm: &str,
        process: bool,
    ) -> Vec<BlockingPin>;
}

/// The mode, over the settings it reads.
pub struct Mode {
    settings: Arc<Settings>,
    /// The (setting, source) pairs whose ignored value has been said, once
    /// per process (STS-CORE-0106): bounded by the table's rows and the
    /// attributes that override them, never by how many entries carry one.
    announced: Mutex<HashSet<String>>,
    bcp_waivers: OnceLock<Arc<dyn OAuthBcpWaivers>>,
    pinned_signers: OnceLock<Arc<dyn PinnedSigners>>,
}

predicates! {
    verifies_credentials = "verifiesCredentials", product;
    auto_creates = "autoCreates", development;
    believes_asserted_selectors = "believesAssertedSelectors", development;
    requires_workload_attestation = "requiresWorkloadAttestation", product;
    serves_unattested_entries = "servesUnattestedEntries", development;
    accepts_credentials_without_status =
        "acceptsCredentialsWithoutStatus", development;
    serves_unattested_workload_tcp = "servesUnattestedWorkloadTcp", development;
    registers_unidentifying_entries =
        "registersUnidentifyingEntries", development;
    trusts_unverified_local_socket = "trustsUnverifiedLocalSocket", development;
    spoils_on_purpose = "spoilsOnPurpose", development;
    requires_confidential_client_authentication =
        "requiresConfidentialClientAuthentication", product;
    enforces_oauth_security_bcp = "enforcesOauthSecurityBcp", product;
    opens_management_api = "opensManagementApi", development;
    seeds_demo_data = "seedsDemoData", development;
    describes_itself_as_test_double =
        "describesItselfAsTestDouble", development;
    rotates_signing_keys = "rotatesSigningKeys", product;
    rotates_kerberos_keys = "rotatesKerberosKeys", product;
    derives_krbtgt_from_password = "derivesKrbtgtFromPassword", development;
    generates_acceptor_key = "generatesAcceptorKey", product;
    refuses_expired_client_secrets = "refusesExpiredClientSecrets", product;
    invents_claim_values = "inventsClaimValues", development;
    creates_incomplete_people = "createsIncompletePeople", development;
    accepts_unregistered_addresses =
        "acceptsUnregisteredAddresses", development;
    requires_cell_kek = "requiresCellKek", product;
    opens_test_controls = "opensTestControls", development;
    opens_console_to_anyone = "opensConsoleToAnyone", development;
    authorizes_directory_writes = "authorizesDirectoryWrites", product;
    authorizes_directory_reads = "authorizesDirectoryReads", product;
    requires_directory_bind = "requiresDirectoryBind", product;
    withholds_directory_secrets = "withholdsDirectorySecrets", product;
    protects_operational_attributes = "protectsOperationalAttributes", product;
    requires_confidential_directory_binds =
        "requiresConfidentialDirectoryBinds", product;
    limits_directory_bind_failures = "limitsDirectoryBindFailures", product;
    sends_weaker_than_asked = "sendsWeakerThanAsked", development;
    refuses_unknown_revocation_status =
        "refusesUnknownRevocationStatus", product;
    refuses_unrevocable_certificates =
        "refusesUnrevocableCertificates", product;
    enforces_paranoid_pki = "enforcesParanoidPki", product;
    requires_pki_for_gnap_mtls = "requiresPkiForGnapMtls", product;
    requires_enrollment_tls = "requiresEnrollmentTls", product;
    opens_introspection = "opensIntrospection", development;
    opens_revocation = "opensRevocation", development;
    accepts_unverified_issuer_tokens =
        "acceptsUnverifiedIssuerTokens", development;
    exchanges_unverified_tokens = "exchangesUnverifiedTokens", development;
    authorizes_delegation = "authorizesDelegation", product;
    grants_undeclared_scopes = "grantsUndeclaredScopes", development;
    issues_through_undeclared_protocols =
        "issuesThroughUndeclaredProtocols", development;
    grants_uncatalogued_access = "grantsUncataloguedAccess", development;
    honours_ungranted_permissions = "honoursUngrantedPermissions", development;
    enrols_keys_on_first_use = "enrolsKeysOnFirstUse", development;
    pins_self_issued_keys_on_first_use =
        "pinsSelfIssuedKeysOnFirstUse", development;
    mints_person_dids_on_request_address =
        "mintsPersonDidsOnRequestAddress", development;
    mints_photo_addresses_on_request_address =
        "mintsPhotoAddressesOnRequestAddress", development;
    accepts_unverified_attestation =
        "acceptsUnverifiedAttestation", development;
    accepts_unattested_device_keys = "acceptsUnattestedDeviceKeys", development;
    refuses_unchecked_attestation_revocation =
        "refusesUncheckedAttestationRevocation",
        product_and(DEVICES_ANDROID_REVOCATION_REQUIRED);
    requires_fresh_key_attestation = "requiresFreshKeyAttestation", product;
    accepts_password_alone_from_second_factor_accounts =
        "acceptsPasswordAloneFromSecondFactorAccounts", development;
    issues_tickets_on_password_alone =
        "issuesTicketsOnPasswordAlone", development;
    requires_sid_filtering_on_trusts = "requiresSidFilteringOnTrusts", product;
    recovers_weaker_than_passkeys = "recoversWeakerThanPasskeys", development;
    matches_federated_names = "matchesFederatedNames", development;
    defaults_federated_autocreate = "defaultsFederatedAutocreate", development;
    accepts_unsigned_federated_logout =
        "acceptsUnsignedFederatedLogout", development;
    accepts_unencrypted_federated_assertions =
        "acceptsUnencryptedFederatedAssertions", development;
    accepts_unsigned_request_objects =
        "acceptsUnsignedRequestObjects", development;
    certifies_request_host = "certifiesRequestHost", development;
    accepts_loose_request_uris = "acceptsLooseRequestUris", development;
    accepts_unsigned_saml_requests = "acceptsUnsignedSamlRequests", development;
    encrypts_to_observed_certificates =
        "encryptsToObservedCertificates", development;
    registers_from_metadata_query = "registersFromMetadataQuery", development;
    publishes_metadata_for_unregistered_providers =
        "publishesMetadataForUnregisteredProviders", development;
    issues_to_unregistered_applications =
        "issuesToUnregisteredApplications", development;
    limits_debugger_destinations = "limitsDebuggerDestinations", product;
    dials_internal_addresses = "dialsInternalAddresses", development;
    skips_outbound_tls_verification =
        "skipsOutboundTlsVerification", development;
    dials_plain_http_outbound = "dialsPlainHttpOutbound", development;
    captures_mail = "capturesMail", development;
    accepts_file_secret_destinations =
        "acceptsFileSecretDestinations", development;
    mails_links_from_listener_address =
        "mailsLinksFromListenerAddress", development;
    accepts_nonconforming_resource_metadata =
        "acceptsNonconformingResourceMetadata", development;
    observes_risk_only = "observesRiskOnly", development;
    uses_broken_algorithms = "usesBrokenAlgorithms", development;
    omits_strict_transport_security =
        "omitsStrictTransportSecurity", development;
    fails_open_on_policy_fault = "failsOpenOnPolicyFault", development;
    restricts_unscoped_people =
        "restrictsUnscopedPeople",
        product_unless(SECURITY_ALLOW_UNSCOPED_PEOPLE);
    confines_named_files = "confinesNamedFiles", product;
    allows_cbc_jwe = "allowsCbcJwe", development_or(CRYPTO_ALLOW_CBC_JWE);
    requires_pkce_of_every_client =
        "requiresPkceOfEveryClient",
        product_unless(OAUTH2_ALLOW_CONFIDENTIAL_WITHOUT_PKCE);
    requires_second_factor_of_everyone =
        "requiresSecondFactorOfEveryone",
        product_unless(AUTHN_ALLOW_OPTIONAL_SECOND_FACTOR);
    requires_tls_to_malware_scanner =
        "requiresTlsToMalwareScanner",
        product_unless(MALWARE_SCAN_ALLOW_CLEARTEXT);
    refuses_token_for_gone_subject = "refusesTokenForGoneSubject", product;
    refuses_assertion_without_audience =
        "refusesAssertionWithoutAudience",
        product_unless(FEDERATION_ALLOW_ASSERTION_WITHOUT_AUDIENCE);
    warns_without_audit_destination = "warnsWithoutAuditDestination", product;
    omits_unapproved_signing_curves = "omitsUnapprovedSigningCurves", product;
    refuses_plain_syslog =
        "refusesPlainSyslog", product_unless(AUDIT_ALLOW_PLAIN_SYSLOG);
    refuses_default_database_password =
        "refusesDefaultDatabasePassword",
        product_unless(PERSISTENCE_ALLOW_DEFAULT_DATABASE_PASSWORD);
    requires_secret_store =
        "requiresSecretStore", product_unless(SECRETS_ALLOW_LOCAL_SECRETS);
    redacts_request_log = "redactsRequestLog", product;
    requires_typed_logout_token =
        "requiresTypedLogoutToken",
        product_unless(FEDERATION_ALLOW_UNTYPED_LOGOUT_TOKEN);
    hides_failure_detail = "hidesFailureDetail", product;
    requires_trusted_proxy_ranges = "requiresTrustedProxyRanges", product;
    refuses_repeated_token_parameters =
        "refusesRepeatedTokenParameters", product;
    requires_evidence_to_clear_factor =
        "requiresEvidenceToClearFactor", product;
    hides_step_ids = "hidesStepIds", product;
    allows_legacy_hashes =
        "allowsLegacyHashes", development_or(CRYPTO_ALLOW_LEGACY_HASHES);
    binds_sign_in_steps = "bindsSignInSteps", product;
    generates_bootstrap_name =
        "generatesBootstrapName", product_unless(ADMIN_ALLOW_DEFAULT_USERNAME);
    revokes_access_tokens_at_sign_out = "revokesAccessTokensAtSignOut", product;
    narrows_undeclared_grants =
        "narrowsUndeclaredGrants",
        product_unless(OAUTH2_ALLOW_UNDECLARED_GRANTS);
    answers_scep = "answersScep", development_or(SCEP_ALLOW_IN_PRODUCT);
    prefixes_cookies = "prefixesCookies", product;
    issues_unsigned_assertions = "issuesUnsignedAssertions", development;
    serves_without_security_header = "servesWithoutSecurityHeader", development;
}

impl Mode {
    pub fn new(settings: Arc<Settings>) -> Mode {
        Mode {
            settings,
            announced: Mutex::new(HashSet::new()),
            bcp_waivers: OnceLock::new(),
            pinned_signers: OnceLock::new(),
        }
    }

    /// Fills the RFC 9700 waivers slot, once.
    pub fn set_bcp_waivers(&self, slot: Arc<dyn OAuthBcpWaivers>) -> bool {
        self.bcp_waivers.set(slot).is_ok()
    }

    /// Fills the pinned-signer slot, once.
    pub fn set_pinned_signers(&self, slot: Arc<dyn PinnedSigners>) -> bool {
        self.pinned_signers.set(slot).is_ok()
    }

    /// The ambient realm's mode: `product`, or `development` for anything
    /// else.
    pub fn current(&self) -> &'static str {
        if self.settings.value(keys::GLOBAL_MODE).as_str() == PRODUCT {
            PRODUCT
        } else {
            DEVELOPMENT
        }
    }

    // Private on purpose: see the module's header.
    fn is_product(&self) -> bool {
        self.current() == PRODUCT
    }

    /// `config.value(key) === true`.
    fn is_on(&self, key: Key) -> bool {
        self.settings.value(key) == SettingValue::Bool(true)
    }

    /// Whether the embedded protocol debugger is served: `debugger.enabled`
    /// `on` or `off` decides, `auto` follows the mode.
    pub fn embeds_protocol_debugger(&self) -> bool {
        let asked = self.settings.value(keys::DEBUGGER_ENABLED);
        match asked.as_str() {
            "on" => true,
            "off" => false,
            _ => !self.is_product(),
        }
    }

    /// The console's gate. Cannot be turned off in either mode.
    pub fn gates_console(&self) -> bool {
        true
    }

    /// SCIM's credential. Cannot be turned off in either mode.
    pub fn gates_scim(&self) -> bool {
        true
    }

    /// Shared Signals' bearer token. Cannot be turned off in either mode.
    pub fn gates_shared_signals(&self) -> bool {
        true
    }

    /// The SPIRE Server API's X509-SVID. Cannot be turned off.
    pub fn gates_spire_server_api(&self) -> bool {
        true
    }

    /// Whether a received SET that does not verify is refused: always in
    /// product, and in development where `ssf.receiveRequireSignature` says.
    pub fn refuses_unverified_signals(&self) -> bool {
        self.is_product() || self.is_on(keys::SSF_RECEIVE_REQUIRE_SIGNATURE)
    }

    /// Whether received signals are recorded and not acted on: development,
    /// unless `ssf.actOnSignalsInDevelopment` is on.
    pub fn observes_signals_only(&self) -> bool {
        !self.is_product()
            && !self.is_on(keys::SSF_ACT_ON_SIGNALS_IN_DEVELOPMENT)
    }

    /// `minScryptParallelism()`: the least scrypt parallelism a new password
    /// is hashed with.
    pub fn min_scrypt_parallelism(&self) -> i64 {
        if self.is_product() {
            3
        } else {
            1
        }
    }

    /// `defaultRsaBits()`: the size of a new RSA key no setting names.
    pub fn default_rsa_bits(&self) -> i64 {
        if self.is_product() {
            3072
        } else {
            2048
        }
    }

    /// `expiredAssertionGraceS()`: the grace on an expired GNAP user
    /// assertion, in seconds — the setting, or 0 in product where nobody set
    /// it (its source is `defaults` or `default`).
    pub fn expired_assertion_grace_s(&self) -> i64 {
        let key = keys::GNAP_ASSERTION_MAX_AGE_S;
        let source = self.settings.source_of(key).as_str();
        if self.is_product() && source.starts_with("default") {
            return 0;
        }
        self.settings.value(key).as_int()
    }

    /// `cleartextStartupProblem(useHttps)`: why this process must not start,
    /// where product mode has the main port in cleartext; empty where it may.
    pub fn cleartext_startup_problem(&self, use_https: bool) -> String {
        if self.is_product() && !use_https {
            return "global.https is off, and product mode serves its main \
                    port over TLS only (ASVS 5.0.0 12.2.1). Unset STS_HTTPS, \
                    or use development mode."
                .to_string();
        }
        String::new()
    }

    /// `certificateWaivers()`: the public-certificate requirement waived
    /// while no `tls.certificateFile` is named.
    pub fn certificate_waivers(&self) -> Vec<Json> {
        // JavaScript's truthiness of a string: anything but "".
        if !self
            .settings
            .value(keys::TLS_CERTIFICATE_FILE)
            .as_str()
            .is_empty()
        {
            return Vec::new();
        }
        vec![json!({
            "requirement": "public-certificate",
            "section": "ASVS 5.0.0 12.2.2",
            "level": "MUST",
            "setting": "tls.certificateFile",
        })]
    }

    /// `accessEnforcementWaivers()`: each of the two access switches an
    /// administrator turned off (`=== false`).
    pub fn access_enforcement_waivers(&self) -> Vec<Json> {
        [keys::XACML_ENFORCE_ACCESS, keys::ROLES_ENFORCE_ISSUANCE]
            .into_iter()
            .filter(|key| {
                self.settings.value(*key) == SettingValue::Bool(false)
            })
            .map(|key| {
                json!({
                    "requirement": "access-by-policy",
                    "section": "ASVS 5.0.0 8.2.1",
                    "level": "MUST",
                    "setting": key.as_str(),
                })
            })
            .collect()
    }

    /// What `mode.js` exports by `name` answers, called with no argument —
    /// `cleartextStartupProblem()` is then asked about a port that is not
    /// HTTPS, as Node's `undefined` is falsy. `None` for a name it does not
    /// export.
    pub fn answer(&self, name: &str) -> Option<Json> {
        let answer = match name {
            "embedsProtocolDebugger" => json!(self.embeds_protocol_debugger()),
            "gatesConsole" => json!(self.gates_console()),
            "gatesScim" => json!(self.gates_scim()),
            "gatesSharedSignals" => json!(self.gates_shared_signals()),
            "gatesSpireServerApi" => json!(self.gates_spire_server_api()),
            "refusesUnverifiedSignals" => {
                json!(self.refuses_unverified_signals())
            }
            "observesSignalsOnly" => json!(self.observes_signals_only()),
            "minScryptParallelism" => json!(self.min_scrypt_parallelism()),
            "defaultRsaBits" => json!(self.default_rsa_bits()),
            "expiredAssertionGraceS" => {
                json!(self.expired_assertion_grace_s())
            }
            "cleartextStartupProblem" => {
                json!(self.cleartext_startup_problem(false))
            }
            "certificateWaivers" => json!(self.certificate_waivers()),
            "accessEnforcementWaivers" => {
                json!(self.access_enforcement_waivers())
            }
            other => json!(self.simple_predicate(other)?),
        };
        Some(answer)
    }

    /// A predicate by its `mode.js` name, as `allowsValue()` reads one — a
    /// settings row's `onlyWhile`: `!!predicate()`, so an answer that is not
    /// a boolean counts by JavaScript's truthiness.
    pub fn predicate(&self, name: &str) -> Option<bool> {
        self.answer(name).map(|answer| js_truthy(&answer))
    }

    /// Whether the mode allows `key` to hold `value`: true for a row with
    /// no marker, for the row's default, for a value `onlyWhileValues`
    /// does not name, and wherever the marker's predicate answers true. A
    /// list is judged element by element (`krb5.enctypes`' `23`).
    pub fn allows_value(&self, key: &str, value: &SettingValue) -> bool {
        let Some(row) = row(key) else {
            return true;
        };
        let Some(predicate) = row.only_while else {
            return true;
        };
        match (value, row.only_while_values) {
            (SettingValue::List(list), Some(_)) => {
                if marked(&self.settings, row, list).is_empty() {
                    return true;
                }
            }
            _ if equals_default(value, row.default) => return true,
            (value, Some(names))
                if !names.contains(&value_text(value).as_str()) =>
            {
                return true;
            }
            _ => {}
        }
        // A marker naming no predicate is a defect in the table; refusing
        // is the direction that cannot loosen anything.
        self.predicate(predicate).unwrap_or(false)
    }

    /// A setting as the ambient realm's mode lets it be.
    pub fn value_in_force(&self, key: &str) -> SettingValue {
        let value = self.settings.value_of(key);
        self.in_force(key, value, key)
    }

    /// A value from anywhere — an application's override of a setting — as
    /// the mode lets it be. A refused value is read as the product value and
    /// said once per process and source (STS-CORE-0106).
    pub fn in_force(
        &self,
        key: &str,
        value: SettingValue,
        source: &str,
    ) -> SettingValue {
        if self.allows_value(key, &value) {
            return value;
        }
        let Some(row) = row(key) else {
            return value;
        };
        let read = product_value(&self.settings, row, &value);
        let said = format!("{}|{}", key, source);
        let first = match self.announced.lock() {
            Ok(mut seen) => seen.insert(said),
            Err(poisoned) => poisoned.into_inner().insert(said),
        };
        if first {
            let who = if source != key {
                format!("{} (overriding {})", source, key)
            } else {
                key.to_string()
            };
            let what = match (&value, row.only_while_values) {
                (SettingValue::List(list), Some(_)) => format!(
                    " names {}, which is IGNORED, ",
                    to_json(&SettingValue::List(marked(
                        &self.settings,
                        row,
                        list
                    )))
                ),
                _ => format!(" is set to {} and is IGNORED, ", to_json(&value)),
            };
            tracing::warn!(
                "{}mode: {}{}because this realm is in product mode \
                 (global.mode=product): {} It is read as {} until it is \
                 reset. Said once per process.",
                tag(codes::STS_CORE_0106),
                who,
                what,
                write_refusal_reason(row.only_while.unwrap_or("")),
                to_json(&read)
            );
        }
        read
    }

    /// The mode's half of a write's check (`config.js`'s
    /// `modeWriteProblem()` and `modeWriteCode()`): a write that would turn
    /// a live pinned signer off, the capture transport in product, and a
    /// development-only value.
    pub fn write_problem(&self, key: &str, raw: &Json) -> Option<Refusal> {
        let row = row(key);
        if key == "pki.pinnedSigners" {
            if let Some(row) = row.filter(|row| row.check(raw).is_none()) {
                if let Some(problem) =
                    self.pinned_signer_problem(&row.parse(Some(raw)))
                {
                    return Some(Refusal {
                        problem,
                        code: codes::STS_PKI_0215,
                    });
                }
            }
        }
        // `String(raw == null ? '' : raw).trim()`.
        let as_text = match raw {
            Json::Null => String::new(),
            other => js_string(other),
        };
        if key == "mail.transport"
            && js_trim(&as_text) == "capture"
            && !self.captures_mail()
        {
            return Some(Refusal {
                problem: "\"mail.transport\" cannot be \"capture\" here: \
                          this realm is in product mode (global.mode=product), \
                          where a captured message would put its body — a \
                          password reset link, a verification link — on the \
                          console. Configure smtp, ses, acs or gmail, or \
                          leave it \"default\" (off)."
                    .to_string(),
                code: codes::STS_MAIL_0003,
            });
        }
        let row = row?;
        let predicate = row.only_while?;
        if row.check(raw).is_some() {
            return None;
        }
        let parsed = row.parse(Some(raw));
        if self.allows_value(key, &parsed) {
            return None;
        }
        let verb = match parsed {
            SettingValue::Bool(true) => "turned on".to_string(),
            SettingValue::Bool(false) => "turned off".to_string(),
            // `'set to ' + raw`: JavaScript's String() of the raw value.
            _ => format!("set to {}", js_string(raw)),
        };
        Some(Refusal {
            problem: format!(
                "\"{}\" cannot be {} here: this realm is in product mode \
                 (global.mode=product), where it is ignored — {}",
                key,
                verb,
                write_refusal_reason(predicate)
            ),
            code: codes::STS_CORE_0103,
        })
    }

    /// `pinnedSignerWriteProblem()` (#263): `pki.pinnedSigners` turned off
    /// while the realm the write lands in holds a live or pending pinned
    /// signing key would make the generated key sign again with no
    /// `signing-key-rotated`.
    fn pinned_signer_problem(&self, parsed: &SettingValue) -> Option<String> {
        if *parsed != SettingValue::Bool(false) {
            return None;
        }
        let slot = self.pinned_signers.get()?;
        let in_realm = self.settings.ambient_realm();
        let realm = if in_realm {
            crate::realm::current_id()
        } else {
            "default".to_string()
        };
        let pins = slot.blocking_signers_off(&realm, !in_realm);
        if pins.is_empty() {
            return None;
        }
        let named: Vec<String> = pins
            .iter()
            .map(|one| {
                format!(
                    "{} {} ({} realm, {})",
                    one.unit,
                    one.kid,
                    one.realm,
                    if one.role == "active" {
                        "signing"
                    } else {
                        "published, not yet signing"
                    }
                )
            })
            .collect();
        Some(format!(
            "\"pki.pinnedSigners\" cannot be turned off while a pinned \
             signing key is live or pending: {}. Turning it off would make \
             the generated key sign again with no signing-key-rotated sent. \
             Unpin first — on /admin/pki, or POST /admin-api/pki/unpin-key — \
             and then turn it off.",
            named.join(", ")
        ))
    }

    /// `checkWrite()`: the settings' own check, then the mode's — for the
    /// doors that write a value somebody asked for.
    pub fn check_write(
        &self,
        key: &str,
        raw: &Json,
        for_realm: Option<bool>,
    ) -> Option<Refusal> {
        self.settings
            .check_override(key, raw, for_realm)
            .or_else(|| self.write_problem(key, raw))
    }

    /// Every row carrying the marker, with the value held and the value in
    /// force — which differ where a development-only value is stored in a
    /// product realm. Read through `allows_value()`, so drawing logs
    /// nothing.
    pub fn development_only_settings(&self) -> Vec<Json> {
        rows()
            .iter()
            .filter_map(|row| {
                let predicate = row.only_while?;
                let stored = self.settings.value_of(row.key);
                let allowed = self.allows_value(row.key, &stored);
                let in_force = if allowed {
                    stored.clone()
                } else {
                    product_value(&self.settings, row, &stored)
                };
                Some(json!({
                    "key": row.key,
                    "group": row.group,
                    "predicate": predicate,
                    "developmentOnlyValues": row.only_while_values,
                    "default": default_json(row.default),
                    "value": to_json(&stored),
                    "inForce": to_json(&in_force),
                    "ignored": !allowed,
                    "why": write_refusal_reason(predicate),
                }))
            })
            .collect()
    }

    /// The whole answer for `/admin/mode`, `GET /admin-api/mode` and the
    /// metadata report. A requirement carries `waived` where an
    /// administrator waived part of it in this realm (#1295): the RFC 9700
    /// rows on `oauth-security-bcp` (whatever the mode), and in product the
    /// access switches on `access-decisions-fail-closed` and the missing
    /// certificate on `public-certificate`.
    pub fn report(&self) -> Json {
        let product = self.is_product();
        let bcp = self
            .bcp_waivers
            .get()
            .map(|slot| slot.waivers())
            .unwrap_or_default();
        let access = if product {
            self.access_enforcement_waivers()
        } else {
            Vec::new()
        };
        let certificate = if product {
            self.certificate_waivers()
        } else {
            Vec::new()
        };
        let requirements: Vec<Json> = requirements()
            .iter()
            .map(|one| {
                let mut row = serde_json::Map::new();
                let chosen = if product { "product" } else { "development" };
                row.insert(
                    "inForce".into(),
                    one.get(chosen).cloned().unwrap_or(Json::Null),
                );
                if let Some(fields) = one.as_object() {
                    for (k, v) in fields {
                        row.insert(k.clone(), v.clone());
                    }
                }
                let waived = match one.get("id").and_then(Json::as_str) {
                    Some("oauth-security-bcp") => &bcp,
                    Some("access-decisions-fail-closed") => &access,
                    Some("public-certificate") => &certificate,
                    _ => &Vec::new(),
                };
                if !waived.is_empty() {
                    row.insert("waived".into(), json!(waived));
                }
                Json::Object(row)
            })
            .collect();
        json!({
            "mode": self.current(),
            "isProduct": product,
            "requirements": requirements,
            "developmentOnlySettings": self.development_only_settings(),
            "notYet": TABLE.get("notYet").cloned().unwrap_or(json!([])),
        })
    }
}

/// The predicate names `mode.js` exports.
pub fn predicate_names() -> Vec<&'static str> {
    TABLE
        .get("predicates")
        .and_then(Json::as_array)
        .map(|list| list.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default()
}

/// REQUIREMENTS: what each mode does, row by row.
pub fn requirements() -> &'static [Json] {
    TABLE
        .get("requirements")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Why a marked row's value is not allowed, by the predicate it names.
pub fn write_refusal_reason(predicate: &str) -> &'static str {
    TABLE
        .get("writeRefusals")
        .and_then(|map| map.get(predicate))
        .or_else(|| TABLE.get("writeRefusalFallback"))
        .and_then(Json::as_str)
        .unwrap_or("the setting is for development mode only.")
}

/// JavaScript's `value === row.dflt`: a scalar against the raw default; a
/// list is never the same object as anything.
fn equals_default(value: &SettingValue, default: DefaultValue) -> bool {
    match (value, default) {
        (SettingValue::Text(text), DefaultValue::Text(d)) => text == d,
        (SettingValue::Int(n), DefaultValue::Int(d)) => *n == d,
        (SettingValue::Bool(b), DefaultValue::Bool(d)) => *b == d,
        _ => false,
    }
}

/// A scalar value as `indexOf()` compares it against `onlyWhileValues`.
fn value_text(value: &SettingValue) -> String {
    match value {
        SettingValue::Text(text) => text.clone(),
        SettingValue::Int(n) => n.to_string(),
        SettingValue::Bool(b) => b.to_string(),
        SettingValue::List(_) => String::new(),
    }
}

/// The elements of a list the row's `onlyWhileValues` names, compared as
/// text — and its `onlyWhileValuesUnless` values too while that setting is
/// not on (#1456).
fn marked(
    settings: &Settings,
    row: &SettingRow,
    list: &[String],
) -> Vec<String> {
    let mut names: Vec<&str> = row.only_while_values.unwrap_or(&[]).to_vec();
    if let Some(unless) = &row.only_while_values_unless {
        if settings.value_of(unless.setting) != SettingValue::Bool(true) {
            names.extend_from_slice(unless.values);
        }
    }
    list.iter()
        .filter(|one| names.contains(&one.as_str()))
        .cloned()
        .collect()
}

/// What a value the mode refuses is read as: the default, or for a list the
/// list without the marked elements — and where nothing would be left, the
/// default without them, so a product KDC is never left offering nothing.
fn product_value(
    settings: &Settings,
    row: &SettingRow,
    value: &SettingValue,
) -> SettingValue {
    let dflt = row.parse(Some(&default_json(row.default)));
    let (SettingValue::List(list), Some(_)) = (value, row.only_while_values)
    else {
        return dflt;
    };
    let withheld = marked(settings, row, list);
    let kept: Vec<String> = list
        .iter()
        .filter(|one| !withheld.contains(one))
        .cloned()
        .collect();
    if !kept.is_empty() {
        return SettingValue::List(kept);
    }
    let fallback = dflt.as_list().to_vec();
    let marked_default = marked(settings, row, &fallback);
    SettingValue::List(
        fallback
            .into_iter()
            .filter(|one| !marked_default.contains(one))
            .collect(),
    )
}

fn default_json(default: DefaultValue) -> Json {
    match default {
        DefaultValue::Text(text) => json!(text),
        DefaultValue::Int(n) => json!(n),
        DefaultValue::Bool(b) => json!(b),
        DefaultValue::List(list) => json!(list),
        DefaultValue::Derived => Json::Null,
    }
}

fn to_json(value: &SettingValue) -> Json {
    match value {
        SettingValue::Text(text) => json!(text),
        SettingValue::Int(n) => json!(n),
        SettingValue::Bool(b) => json!(b),
        SettingValue::List(list) => json!(list),
    }
}

/// JavaScript's truthiness of a predicate's answer: `!!answer`.
fn js_truthy(answer: &Json) -> bool {
    match answer {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Json::String(text) => !text.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn mode(mode: &str) -> Mode {
        let mut env = HashMap::new();
        env.insert("STS_MODE".to_string(), mode.to_string());
        Mode::new(Arc::new(Settings::new(Json::Null, env)))
    }

    #[test]
    fn every_node_predicate_is_answered() {
        let names = predicate_names();
        assert_eq!(names.len(), 126);
        let m = mode(PRODUCT);
        let missing: Vec<&&str> =
            names.iter().filter(|n| m.answer(n).is_none()).collect();
        assert!(missing.is_empty(), "{:?}", missing);
        for row in rows() {
            if let Some(p) = row.only_while {
                assert!(m.predicate(p).is_some(), "{} names {}", row.key, p);
            }
        }
    }

    #[test]
    fn the_modes_answer_opposite_questions() {
        let product = mode(PRODUCT);
        let development = mode(DEVELOPMENT);
        assert!(product.verifies_credentials());
        assert!(!development.verifies_credentials());
        assert!(development.seeds_demo_data());
        assert!(!product.seeds_demo_data());
        assert!(product.gates_console() && development.gates_console());
        assert!(development.embeds_protocol_debugger());
        assert!(!product.embeds_protocol_debugger());
        assert_eq!(mode("nonsense").current(), DEVELOPMENT);
    }

    #[test]
    fn a_development_only_value_in_product() {
        let product = mode(PRODUCT);
        let development = mode(DEVELOPMENT);
        let key = rows()
            .iter()
            .find(|r| {
                r.only_while.is_some()
                    && r.only_while_values.is_none()
                    && r.default == DefaultValue::Bool(false)
            })
            .map(|r| r.key)
            .unwrap_or("");
        assert!(!key.is_empty());
        assert!(product.allows_value(key, &SettingValue::Bool(false)));
        assert!(!product.allows_value(key, &SettingValue::Bool(true)));
        assert!(development.allows_value(key, &SettingValue::Bool(true)));
        let refused = product.write_problem(key, &json!(true));
        assert!(refused.is_some_and(|r| r.code == codes::STS_CORE_0103
            && r.problem.contains("cannot be turned on")));
        assert_eq!(
            product.in_force(key, SettingValue::Bool(true), key),
            SettingValue::Bool(false)
        );
    }

    #[test]
    fn a_marked_element_of_a_list() {
        let product = mode(PRODUCT);
        let enctypes = product.value_in_force("krb5.enctypes");
        assert!(!enctypes.as_list().iter().any(|e| e == "23"));
        assert!(!enctypes.as_list().is_empty());
        let only_rc4 = SettingValue::List(vec!["23".into()]);
        let read = product.in_force("krb5.enctypes", only_rc4, "test");
        assert!(!read.as_list().is_empty());
        assert!(!read.as_list().iter().any(|e| e == "23"));
    }

    #[test]
    fn capture_is_refused_in_product() {
        let refused =
            mode(PRODUCT).write_problem("mail.transport", &json!("capture"));
        assert!(refused.is_some_and(|r| r.code == codes::STS_MAIL_0003));
        assert!(mode(DEVELOPMENT)
            .write_problem("mail.transport", &json!("capture"))
            .is_none());
    }

    #[test]
    fn the_report() {
        let report = mode(PRODUCT).report();
        assert_eq!(report["mode"], "product");
        assert_eq!(report["requirements"].as_array().map(Vec::len), Some(112));
        assert_eq!(
            report["requirements"][0]["inForce"],
            report["requirements"][0]["product"]
        );
        assert!(report["developmentOnlySettings"]
            .as_array()
            .is_some_and(|rows| rows.len() == 34));
        // No certificate file is named, so product waives the requirement.
        let certificate = report["requirements"]
            .as_array()
            .and_then(|rows| {
                rows.iter().find(|r| r["id"] == "public-certificate")
            })
            .cloned()
            .unwrap_or(Json::Null);
        assert_eq!(certificate["waived"][0]["setting"], "tls.certificateFile");
        let development = mode(DEVELOPMENT).report();
        assert!(development["requirements"].as_array().is_some_and(|rows| {
            rows.iter().all(|r| r.get("waived").is_none())
        }));
    }

    #[test]
    fn the_answers_that_are_not_booleans() {
        let product = mode(PRODUCT);
        let development = mode(DEVELOPMENT);
        assert_eq!(product.answer("defaultRsaBits"), Some(json!(3072)));
        assert_eq!(development.answer("minScryptParallelism"), Some(json!(1)));
        assert_eq!(product.expired_assertion_grace_s(), 0);
        assert!(product.cleartext_startup_problem(false).contains("ASVS"));
        assert!(product.cleartext_startup_problem(true).is_empty());
        assert!(development.cleartext_startup_problem(false).is_empty());
        assert_eq!(product.predicate("certificateWaivers"), Some(true));
        assert_eq!(product.answer("prose"), None);
    }
}
