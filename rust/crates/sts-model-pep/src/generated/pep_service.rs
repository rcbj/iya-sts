// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/pep/ (#1830) by models/lib/pep_lib.mjs, through
// models/lib/rust_lib.mjs (#444, D15). Do not edit: change the model and
// run tests/tools/regenerate-pep-model.sh. tests/model_pep.js fails when
// this differs.

pub mod components {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ApplicablePolicyKind {
        #[serde(rename = "PolicySet")]
        PolicySet,
        #[serde(rename = "Policy")]
        Policy,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ApplicablePolicy {
        pub kind: ApplicablePolicyKind,
        pub id: String,
        pub version: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuthzenAnswered {
        pub decisions: i64,
        #[serde(rename = "true")]
        pub true_: i64,
        #[serde(rename = "false")]
        pub false_: i64,
        pub errors: i64,
        pub forwarded: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuthzenSettings {
        pub enabled: bool,
        #[serde(rename = "resolveSubjectTypes")]
        pub resolve_subject_types: Vec<String>,
        #[serde(rename = "batchEnabled")]
        pub batch_enabled: bool,
        #[serde(rename = "maxEvaluations")]
        pub max_evaluations: i64,
        #[serde(rename = "maxBodyBytes")]
        pub max_body_bytes: i64,
        #[serde(rename = "returnReasons")]
        pub return_reasons: bool,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuthzenStatus {
        #[serde(rename = "pulledCallers")]
        pub pulled_callers: crate::pep_service::components::PulledCallers,
        pub catalogue: crate::pep_service::components::Catalogue,
        pub answered: crate::pep_service::components::AuthzenAnswered,
        /// Whether the edge PDP answers: the value in force, the service's managed
        /// authzen when it set one, else PEP_AUTHZEN (settings.values.authzen says
        /// which).
        pub enabled: bool,
        pub endpoints: Vec<String>,
        #[serde(rename = "localCallers")]
        pub local_callers: crate::pep_service::components::LocalCallers,
        /// https.asksForClientCertificates: whether the environment's HTTPS
        /// listener asks. Admission asks the listener each request arrived on.
        #[serde(rename = "clientCertificatesAsked")]
        pub client_certificates_asked: bool,
        /// The identifier in force: the service's managed authzenPdpIdentifier when
        /// it set one, else PEP_AUTHZEN_PDP_IDENTIFIER; null when neither is, and
        /// the metadata names the origin each request arrived at.
        #[serde(rename = "pdpIdentifier")]
        pub pdp_identifier: Option<String>,
        pub what: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Build {
        pub number: Option<String>,
        pub release: bool,
        pub commit: Option<String>,
        pub at: String,
        pub stamped: bool,
        pub what: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Catalogue {
        pub loaded: bool,
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        pub realm: String,
        #[serde(rename = "apiObject")]
        pub api_object: bool,
        pub rows: i64,
        #[serde(rename = "fgaApplications")]
        pub fga_applications: i64,
        pub refused: Vec<String>,
        #[serde(rename = "leftOutByThePdp")]
        pub left_out_by_the_pdp: i64,
        pub settings: crate::pep_service::components::AuthzenSettings,
        #[serde(rename = "lastPullAt")]
        pub last_pull_at: String,
        #[serde(rename = "lastPullOk")]
        pub last_pull_ok: bool,
        #[serde(rename = "lastPullWhy")]
        pub last_pull_why: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DecidedBy {
        pub pep: String,
        /// The policy set's sync token; empty before any pull.
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        pub note: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum DecisionDecision {
        #[serde(rename = "Permit")]
        Permit,
        #[serde(rename = "Deny")]
        Deny,
        #[serde(rename = "NotApplicable")]
        NotApplicable,
        #[serde(rename = "Indeterminate")]
        Indeterminate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum DecisionBias {
        #[serde(rename = "deny-biased")]
        DenyBiased,
        #[serde(rename = "permit-biased")]
        PermitBiased,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Decision {
        pub decision: DecisionDecision,
        pub allowed: bool,
        pub bias: DecisionBias,
        pub why: String,
        pub status: crate::pep_service::components::DecisionStatus,
        pub obligations: Vec<crate::pep_service::components::Obligation>,
        /// Advice ids.
        pub advice: Vec<String>,
        #[serde(rename = "applicablePolicies")]
        pub applicable_policies: Vec<crate::pep_service::components::ApplicablePolicy>,
        #[serde(rename = "decidedBy")]
        pub decided_by: crate::pep_service::components::DecidedBy,
        pub pip: crate::pep_service::components::PipReport,
        /// Present only when no root policy is held (STS-XPEP-0005).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum DecisionStatusCode {
        #[serde(rename = "urn:oasis:names:tc:xacml:1.0:status:ok")]
        UrnOasisNamesTcXacml10StatusOk,
        #[serde(rename = "urn:oasis:names:tc:xacml:1.0:status:missing-attribute")]
        UrnOasisNamesTcXacml10StatusMissingAttribute,
        #[serde(rename = "urn:oasis:names:tc:xacml:1.0:status:syntax-error")]
        UrnOasisNamesTcXacml10StatusSyntaxError,
        #[serde(rename = "urn:oasis:names:tc:xacml:1.0:status:processing-error")]
        UrnOasisNamesTcXacml10StatusProcessingError,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DecisionStatus {
        pub code: DecisionStatusCode,
        /// Absent, not null, when the engine gave none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Enforced {
        pub decisions: i64,
        pub allowed: i64,
        pub refused: i64,
        pub undischargeable: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Health {
        pub message: String,
    }

    /// start, poll, nudge, heartbeat or unnamed; empty before any change.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum HoldingLastChangeCause {
        #[serde(rename = "")]
        Empty,
        #[serde(rename = "start")]
        Start,
        #[serde(rename = "poll")]
        Poll,
        #[serde(rename = "nudge")]
        Nudge,
        #[serde(rename = "heartbeat")]
        Heartbeat,
        #[serde(rename = "unnamed")]
        Unnamed,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum HoldingLastNudgeResult {
        #[serde(rename = "")]
        Empty,
        #[serde(rename = "failed")]
        Failed,
        #[serde(rename = "changed")]
        Changed,
        #[serde(rename = "unchanged")]
        Unchanged,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Holding {
        pub loaded: bool,
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        /// The root policy's id, "(unnamed)" when it has none; null when none is
        /// held.
        pub root: Option<String>,
        #[serde(rename = "policyCount")]
        pub policy_count: i64,
        #[serde(rename = "lastPullAt")]
        pub last_pull_at: String,
        #[serde(rename = "lastPullOk")]
        pub last_pull_ok: bool,
        #[serde(rename = "lastPullWhy")]
        pub last_pull_why: String,
        /// start, poll, nudge, heartbeat or unnamed; empty before any change.
        #[serde(rename = "lastChangeCause")]
        pub last_change_cause: HoldingLastChangeCause,
        #[serde(rename = "lastChangeAt")]
        pub last_change_at: String,
        #[serde(rename = "lastNudgeAt")]
        pub last_nudge_at: String,
        #[serde(rename = "lastNudgeResult")]
        pub last_nudge_result: HoldingLastNudgeResult,
        pub refused: Vec<crate::pep_service::components::RefusedPolicy>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Https {
        pub configured: bool,
        pub listening: bool,
        pub port: Option<i64>,
        pub certificate: Option<crate::pep_service::components::ServedCertificate>,
        #[serde(rename = "loadedAt")]
        pub loaded_at: Option<String>,
        #[serde(rename = "lastCheckedAt")]
        pub last_checked_at: Option<String>,
        /// What the listener does: the acceptor it serves asks callers for a
        /// certificate (PEP_AUTHZEN_CLIENT_CA or trust anchors set, and its
        /// tuning's askClientCertificate or requireClientCertificate on); before it
        /// serves one, what its tuning will build.
        #[serde(rename = "asksForClientCertificates")]
        pub asks_for_client_certificates: bool,
        pub problem: Option<String>,
        pub what: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LibrarySessions {
        pub held: i64,
        pub max: i64,
        #[serde(rename = "ttlSec")]
        pub ttl_sec: i64,
        pub evicted: i64,
        pub expired: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LocalCallers {
        pub configured: bool,
        pub certificates: i64,
        pub role: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NotFound {
        pub error: String,
        /// Absent on a CRL lookup that found nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error_description: Option<String>,
    }

    /// What the service sends (POST, https only, the PEP's certificate verified
    /// against the realm's pep-tls chain, redirects not followed) after a commit to
    /// the policy repository, to every member of a cluster whose configuration
    /// changed, and on a Sync from the console. The PEP reads full alone and trusts
    /// nothing else in it.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Nudge {
        pub event: String,
        /// When, ISO 8601.
        pub at: String,
        /// The realm's PDP: the base /xacml/pep/* is served under, realm prefix
        /// included — pinned, or that of the request that made the change; empty
        /// only with neither. Not read by the PEP.
        pub pdp: String,
        /// true on a Sync from the console: pull every document whole rather than
        /// answered 304. Honoured at most once a poll interval (STS-XPEP-0120 logs
        /// one asked for sooner, which pulls as usual); absent, false or any other
        /// value is an ordinary pull.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub full: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Obligation {
        pub id: String,
        pub discharged: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum OverviewBias {
        #[serde(rename = "deny-biased")]
        DenyBiased,
        #[serde(rename = "permit-biased")]
        PermitBiased,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Overview {
        pub what: String,
        pub pip: crate::pep_service::components::Pip,
        /// M.N.O.<build>.
        pub version: String,
        pub build: crate::pep_service::components::Build,
        /// The PDP's base URL, PEP_PDP_URL.
        pub pdp: String,
        pub bias: OverviewBias,
        #[serde(rename = "protectedAt")]
        pub protected_at: String,
        pub https: crate::pep_service::components::Https,
        pub authzen: crate::pep_service::components::AuthzenStatus,
        pub proxy: crate::pep_service::components::ProxyStatus,
        pub holding: crate::pep_service::components::Holding,
        /// lastPullAt is empty, unreadable, or older than staleAfterMs.
        pub stale: bool,
        #[serde(rename = "staleAfterMs")]
        pub stale_after_ms: i64,
        pub registration: crate::pep_service::components::Registration,
        pub enforced: crate::pep_service::components::Enforced,
        /// The https notify URL in force; null when none is, or the one set was
        /// refused.
        pub notify: Option<String>,
        pub poll: crate::pep_service::components::Poll,
        pub settings: crate::pep_service::components::Settings,
        pub contract: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Pip {
        pub enabled: bool,
        /// {pdp}/xacml/pip when enabled.
        pub endpoint: Option<String>,
        pub credentialed: bool,
        /// The last evaluation's report, the reverse proxy's included; null before
        /// any.
        #[serde(rename = "lastQuery")]
        pub last_query: Option<crate::pep_service::components::PipReport>,
        pub what: String,
    }

    /// What the PIP did for the last evaluation. One of seven forms: used is false
    /// with why (PIP off; no subject; no designators, with subject; too many
    /// designators, with subject and designators; the query failed or its answer
    /// was unreadable, with subject, designators and failed), or used is true with
    /// subject, designators, resolved and unresolved.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PipReport {
        pub used: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub designators: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resolved: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unresolved: Option<Vec<crate::pep_service::components::Unresolved>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Poll {
        #[serde(rename = "intervalMs")]
        pub interval_ms: i64,
        #[serde(rename = "heartbeatMs")]
        pub heartbeat_ms: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyAnswered {
        pub requests: i64,
        pub forwarded: i64,
        /// Answers by HTTP status, the status as the key.
        #[serde(rename = "byStatus")]
        pub by_status: serde_json::Map<String, serde_json::Value>,
        #[serde(rename = "signIns")]
        pub sign_ins: i64,
        #[serde(rename = "sessionsEnded")]
        pub sessions_ended: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyPorts {
        pub http: i64,
        pub https: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxySessions {
        pub live: i64,
        #[serde(rename = "signInsInFlight")]
        pub sign_ins_in_flight: i64,
        pub max: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxySignals {
        pub receivers: i64,
        pub healthy: i64,
        pub stale: i64,
        #[serde(rename = "staleAfterMs")]
        pub stale_after_ms: i64,
        #[serde(rename = "pollIntervalMs")]
        pub poll_interval_ms: i64,
        #[serde(rename = "oldestSuccessAgeMs")]
        pub oldest_success_age_ms: Option<i64>,
        #[serde(rename = "mostConsecutiveFailures")]
        pub most_consecutive_failures: i64,
        #[serde(rename = "setsAccepted")]
        pub sets_accepted: i64,
        #[serde(rename = "setsRefused")]
        pub sets_refused: i64,
        #[serde(rename = "sessionsEnded")]
        pub sessions_ended: i64,
        #[serde(rename = "librarySessions")]
        pub library_sessions: crate::pep_service::components::LibrarySessions,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyStatus {
        pub enabled: bool,
        pub ports: crate::pep_service::components::ProxyPorts,
        pub loaded: bool,
        pub configured: bool,
        pub active: bool,
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        pub routes: i64,
        #[serde(rename = "publicRoutes")]
        pub public_routes: i64,
        #[serde(rename = "unusableRoutes")]
        pub unusable_routes: i64,
        #[serde(rename = "routesByMechanism")]
        pub routes_by_mechanism: crate::pep_service::components::RoutesByMechanism,
        #[serde(rename = "sessionClients")]
        pub session_clients: i64,
        #[serde(rename = "relyingParties")]
        pub relying_parties: i64,
        #[serde(rename = "signalsReceivers")]
        pub signals_receivers: i64,
        #[serde(rename = "signingCertificates")]
        pub signing_certificates: i64,
        /// Null when the proxy is not running.
        pub signals: Option<crate::pep_service::components::ProxySignals>,
        #[serde(rename = "lastPullAt")]
        pub last_pull_at: String,
        #[serde(rename = "lastPullOk")]
        pub last_pull_ok: bool,
        #[serde(rename = "lastPullWhy")]
        pub last_pull_why: String,
        pub answered: crate::pep_service::components::ProxyAnswered,
        pub sessions: crate::pep_service::components::ProxySessions,
        pub what: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PulledCallers {
        pub loaded: bool,
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        pub door: String,
        pub callers: i64,
        pub certificates: i64,
        #[serde(rename = "truncatedByThePdp")]
        pub truncated_by_the_pdp: bool,
        pub refused: Vec<String>,
        #[serde(rename = "lastPullAt")]
        pub last_pull_at: String,
        #[serde(rename = "lastPullOk")]
        pub last_pull_ok: bool,
        #[serde(rename = "lastPullWhy")]
        pub last_pull_why: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RefusedPolicy {
        pub name: String,
        pub why: String,
    }

    /// registered false: name, attempts and why. registered true adds authenticated
    /// and notify.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Registration {
        pub registered: bool,
        pub name: String,
        pub attempts: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authenticated: Option<bool>,
        pub why: String,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub notify: Option<Option<crate::pep_service::components::RegistrationNotify>>,
    }

    /// The service's register answer's notify member, passed through as it came
    /// (POST /xacml/pep/register). The PEP reads usable and why.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct RegistrationNotify {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub usable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RoutesByMechanism {
        pub session: i64,
        pub oauth2: i64,
        pub saml2: i64,
        pub basic: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ServedCertificate {
        pub subject: String,
        pub issuer: String,
        #[serde(rename = "serialHex")]
        pub serial_hex: String,
        #[serde(rename = "subjectAltName")]
        pub subject_alt_name: String,
        #[serde(rename = "validFrom")]
        pub valid_from: String,
        #[serde(rename = "validTo")]
        pub valid_to: String,
        pub fingerprint256: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum SettingValueSource {
        #[serde(rename = "service")]
        Service,
        #[serde(rename = "environment")]
        Environment,
        #[serde(rename = "derived")]
        Derived,
        #[serde(rename = "default")]
        Default,
    }

    /// One managed setting in force: its value (typed by its key), where it came
    /// from, and rejected: true on a notifyUrl that was set and refused, whose
    /// value is then the refused string.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SettingValue {
        pub value: crate::unions::BoolOrIntegerOrString,
        pub source: SettingValueSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rejected: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Settings {
        pub token: String,
        /// Every managed setting, by key: description, resource, notifyUrl, bias,
        /// pip, pollIntervalMs, heartbeatIntervalMs, backoffMaxMs, timeoutMs,
        /// maxBodyBytes, httpsReloadIntervalMs, logLevel, authzen,
        /// authzenPdpIdentifier, authzenForwardTimeoutMs and the proxy's settings.
        pub values: serde_json::Map<String, serde_json::Value>,
        #[serde(rename = "lastPullAt")]
        pub last_pull_at: String,
        #[serde(rename = "lastPullOk")]
        pub last_pull_ok: bool,
        #[serde(rename = "lastPullWhy")]
        pub last_pull_why: String,
        pub offered: bool,
        pub configured: bool,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Unresolved {
        #[serde(rename = "attributeId")]
        pub attribute_id: String,
        pub why: String,
    }

}

/// What this PEP holds and how it is doing
pub mod get_overview {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/";
    pub const OPERATION_ID: &str = "getOverview";

    pub type Answer200 = crate::pep_service::components::Overview;
}

/// A CRL of this PEP's own credential
pub mod get_crl {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/crl/{name}";
    pub const OPERATION_ID: &str = "getCrl";
}

/// Liveness
pub mod get_healthcheck {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/healthcheck";
    pub const OPERATION_ID: &str = "getHealthcheck";

    pub type Answer200 = crate::pep_service::components::Health;
}

/// The PDP's nudge: pull now
pub mod post_notify {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/notify";
    pub const OPERATION_ID: &str = "postNotify";

    pub type Body = crate::pep_service::components::Nudge;
}

/// The demonstration decision
pub mod get_protected {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/protected";
    pub const OPERATION_ID: &str = "getProtected";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        #[serde(rename = "subjectKind", default, skip_serializing_if = "Option::is_none")]
        pub subject_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    }

    pub type Answer200 = crate::pep_service::components::Decision;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "postNotify" => Some(serde_json::from_value::<post_notify::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getOverview", 200) => Some(serde_json::from_value::<get_overview::Answer200>(value.clone()).map(|_| ())),
        ("getHealthcheck", 200) => Some(serde_json::from_value::<get_healthcheck::Answer200>(value.clone()).map(|_| ())),
        ("getProtected", 200) => Some(serde_json::from_value::<get_protected::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
