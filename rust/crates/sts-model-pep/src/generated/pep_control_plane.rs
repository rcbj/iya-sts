// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/pep/ (#1830) by models/lib/pep_lib.mjs, through
// models/lib/rust_lib.mjs (#444, D15). Do not edit: change the model and
// run tests/tools/regenerate-pep-model.sh. tests/model_pep.js fails when
// this differs.

pub mod components {
    /// The realm's authzen.callerAuthentication. The edge admits callers only when
    /// it is mtls.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum AuthzenCallersDoor {
        #[serde(rename = "mtls")]
        Mtls,
        #[serde(rename = "bearer")]
        Bearer,
        #[serde(rename = "mtls+bearer")]
        MtlsBearer,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuthzenCallers {
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        pub realm: String,
        /// The realm's authzen.callerAuthentication. The edge admits callers only
        /// when it is mtls.
        pub door: AuthzenCallersDoor,
        pub role: String,
        pub group: String,
        /// Sorted by name; empty unless door is mtls.
        pub callers: Vec<crate::pep_control_plane::components::EdgeCaller>,
        pub truncated: bool,
        pub counts: crate::pep_control_plane::components::CallerCounts,
        pub note: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuthzenCatalogue {
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        /// The realm's id; empty for the default realm.
        pub realm: String,
        /// sts-authzen-api when the realm has the API's resource object.
        #[serde(rename = "apiObject")]
        pub api_object: Option<String>,
        pub rows: Vec<crate::pep_control_plane::components::CatalogueRow>,
        /// Rows left out of the catalogue (STS-AUTHZEN-0060).
        #[serde(rename = "leftOut")]
        pub left_out: i64,
        pub settings: crate::pep_control_plane::components::AuthzenSettings,
        /// Applications enforcing fine-grained authorization, whose evaluations the
        /// PEP forwards; each non-empty, at most 256 characters, or the PEP refuses
        /// the whole catalogue.
        #[serde(rename = "fgaApplications", default, skip_serializing_if = "Option::is_none")]
        pub fga_applications: Option<Vec<String>>,
        pub note: String,
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
        /// The realm's authzen.obligationsProfile. Absent on an older catalogue is
        /// read as off: the edge hands no obligation.
        #[serde(rename = "obligationsProfile")]
        pub obligations_profile: bool,
        /// The realm's authzen.tokenExchange: on, the edge answers 501
        /// (STS-XPEP-0140) to every tuple the service answers by the binding's
        /// fixed rules. Absent on an older catalogue is read as on.
        #[serde(rename = "tokenExchange")]
        pub token_exchange: bool,
        /// The authorization_details types the realm's applications declare, which
        /// make a tuple beside a token-exchange gate a detail tuple. null when the
        /// service could not read them (STS-AUTHZEN-0145); null or absent, every
        /// other resource type beside a gate is read as one.
        #[serde(rename = "tokenExchangeDetailTypes")]
        pub token_exchange_detail_types: Option<Vec<String>>,
        /// The token types a token-exchange gate (issue:<token
        /// type>:token_exchange) may name. Absent, every well-formed one is read as
        /// registered.
        #[serde(rename = "tokenExchangeTokenTypes")]
        pub token_exchange_token_types: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BasicRequest {
        pub username: String,
        pub password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    /// valid false alone, or valid true with username, sub and a ticket: opaque,
    /// bound to this PEP, good for 120 s, the evidence the identity door takes.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BasicValidation {
        pub valid: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ticket: Option<String>,
    }

    /// Not read by the PEP.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum CallerCertificateSource {
        #[serde(rename = "stored")]
        Stored,
        #[serde(rename = "issued")]
        Issued,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CallerCertificate {
        /// 64 hex digits; colons allowed.
        pub sha256: String,
        /// Not read by the PEP.
        pub source: CallerCertificateSource,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CallerCounts {
        pub members: i64,
        pub read: i64,
        pub unlocated: i64,
        pub unnamed: i64,
        #[serde(rename = "notAdmitted")]
        pub not_admitted: i64,
        pub unreadable: i64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum CatalogueRowObject {
        #[serde(rename = "subject")]
        Subject,
        #[serde(rename = "resource")]
        Resource,
        #[serde(rename = "action")]
        Action,
        #[serde(rename = "context")]
        Context,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum CatalogueRowMultiplicity {
        #[serde(rename = "single")]
        Single,
        #[serde(rename = "bag")]
        Bag,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CatalogueRow {
        pub object: CatalogueRowObject,
        /// A dotted path of at most six segments of [A-Za-z0-9_$@:-]{1,64}.
        pub property: String,
        #[serde(rename = "attributeId")]
        pub attribute_id: String,
        pub category: String,
        #[serde(rename = "dataType")]
        pub data_type: String,
        pub multiplicity: CatalogueRowMultiplicity,
        /// Only when not empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum EdgeCallerEndpointsItem {
        #[serde(rename = "evaluation")]
        Evaluation,
        #[serde(rename = "evaluations")]
        Evaluations,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct EdgeCaller {
        /// The caller's verified DN.
        pub name: String,
        pub certificates: Vec<crate::pep_control_plane::components::CallerCertificate>,
        pub applications: Vec<String>,
        pub endpoints: Vec<EdgeCallerEndpointsItem>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct EnvironmentTuning {
        #[serde(rename = "api-http")]
        pub api_http: crate::pep_control_plane::components::ListenerTuning,
        #[serde(rename = "api-https")]
        pub api_https: crate::pep_control_plane::components::ListenerTuning,
        #[serde(rename = "proxy-http")]
        pub proxy_http: crate::pep_control_plane::components::ListenerTuning,
        #[serde(rename = "proxy-https")]
        pub proxy_https: crate::pep_control_plane::components::ListenerTuning,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ErrorError {
        #[serde(rename = "not_implemented")]
        NotImplemented,
        #[serde(rename = "access_denied")]
        AccessDenied,
        #[serde(rename = "invalid_client")]
        InvalidClient,
        #[serde(rename = "invalid_request")]
        InvalidRequest,
        #[serde(rename = "invalid_token")]
        InvalidToken,
        #[serde(rename = "insufficient_scope")]
        InsufficientScope,
        #[serde(rename = "use_dpop_nonce")]
        UseDpopNonce,
        #[serde(rename = "server_error")]
        ServerError,
        #[serde(rename = "too_many_requests")]
        TooManyRequests,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Error {
        pub error: ErrorError,
        pub error_description: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatAnswer {
        pub acknowledged: bool,
        pub name: String,
        /// The repository's current token, not the PEP's.
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        /// Whether the PEP holds the current policy set: the one member the PEP
        /// reads; false makes it pull.
        pub current: bool,
        pub action: String,
    }

    /// container (the xacml-pep image) or embedded (a PEP inside an authentication
    /// library, #2026). Absent keeps the registered kind. Anything else is 400
    /// STS-XACML-0342.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum HeartbeatRequestKind {
        #[serde(rename = "container")]
        Container,
        #[serde(rename = "embedded")]
        Embedded,
    }

    /// An embedded PEP's mode: central (every decision asked of POST
    /// /access/v1/evaluation) or local (the bound application's policies pulled and
    /// decided in process). Required for an embedded PEP (400 STS-XACML-0342
    /// otherwise); with a container it is 400 STS-XACML-0341.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum HeartbeatRequestMode {
        #[serde(rename = "central")]
        Central,
        #[serde(rename = "local")]
        Local,
    }

    /// An embedded PEP's report (D4 of #1206): whether the stream of the
    /// application it is embedded in can carry pep-policies-changed. none: the host
    /// has no signal stream and the PEP polls; requested: the stream asks for it;
    /// excluded: the application's ssfEvents leaves it out; down: the stream is not
    /// running or not healthy. Anything else is 400 STS-XACML-0342.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum HeartbeatRequestPolicyEvents {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "requested")]
        Requested,
        #[serde(rename = "excluded")]
        Excluded,
        #[serde(rename = "down")]
        Down,
    }

    /// Absent keeps what the service holds; null clears signals, settings and
    /// listeners; a value replaces it. The counters are set, not added. A member
    /// the PEP's entry stores that carries a value the service cannot hold refuses
    /// the whole heartbeat, 400 STS-XACML-0331 naming the member, and nothing of it
    /// is recorded: a counter that is not a non-negative integer of at most 2^53 -
    /// 1, a text member that is not a string (or null) or carries a control
    /// character, or signals, settings or listeners that are not an object or null.
    /// Within signals and listeners a value is held to its member instead: a count
    /// that is not a non-negative integer is 0, and an age that is not one, or is
    /// older than the epoch, is no time.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatRequest {
        /// Read only when no certificate was presented.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// The policy set held, empty if none.
        #[serde(rename = "syncToken", default, skip_serializing_if = "Option::is_none")]
        pub sync_token: Option<String>,
        #[serde(rename = "policyCount", default, skip_serializing_if = "Option::is_none")]
        pub policy_count: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decisions: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub undischargeable: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bias: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        #[serde(rename = "notifyUrl", default, skip_serializing_if = "Option::is_none")]
        pub notify_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub hostname: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub settings: Option<Option<crate::pep_control_plane::components::SettingsReport>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub signals: Option<Option<crate::pep_control_plane::components::PepSignals>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub listeners: Option<Option<crate::pep_control_plane::components::ListenersReport>>,
        /// container (the xacml-pep image) or embedded (a PEP inside an
        /// authentication library, #2026). Absent keeps the registered kind.
        /// Anything else is 400 STS-XACML-0342.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<HeartbeatRequestKind>,
        /// An embedded PEP's application: its identifier in the realm's registry.
        /// It must be the application the PEP's entry is bound to
        /// (stsPepApplication): bound to none is 403 STS-XACML-0338, another or
        /// none named 403 STS-XACML-0339. Ignored for a container.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        /// An embedded PEP's mode: central (every decision asked of POST
        /// /access/v1/evaluation) or local (the bound application's policies pulled
        /// and decided in process). Required for an embedded PEP (400
        /// STS-XACML-0342 otherwise); with a container it is 400 STS-XACML-0341.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<HeartbeatRequestMode>,
        /// The PEP protocol version the PEP's package speaks. The service supports
        /// 1; any other, or none from an embedded PEP, is 400 STS-XACML-0340.
        #[serde(rename = "protocolVersion", default, skip_serializing_if = "Option::is_none")]
        pub protocol_version: Option<i64>,
        /// An embedded PEP's report (D4 of #1206): whether the stream of the
        /// application it is embedded in can carry pep-policies-changed. none: the
        /// host has no signal stream and the PEP polls; requested: the stream asks
        /// for it; excluded: the application's ssfEvents leaves it out; down: the
        /// stream is not running or not healthy. Anything else is 400
        /// STS-XACML-0342.
        #[serde(rename = "policyEvents", default, skip_serializing_if = "Option::is_none")]
        pub policy_events: Option<HeartbeatRequestPolicyEvents>,
    }

    /// By the route's identity.mode. headers: claims (groups and amr are lists; a
    /// claim with no value is left out). jwt: accessToken, tokenType and expiresIn.
    /// saml: samlResponse, acsUrl and notOnOrAfter.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IdentityAnswer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "accessToken", default, skip_serializing_if = "Option::is_none")]
        pub access_token: Option<String>,
        #[serde(rename = "tokenType", default, skip_serializing_if = "Option::is_none")]
        pub token_type: Option<String>,
        #[serde(rename = "expiresIn", default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<i64>,
        /// The SAML Response's XML, base64.
        #[serde(rename = "samlResponse", default, skip_serializing_if = "Option::is_none")]
        pub saml_response: Option<String>,
        #[serde(rename = "acsUrl", default, skip_serializing_if = "Option::is_none")]
        pub acs_url: Option<String>,
        #[serde(rename = "notOnOrAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_on_or_after: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum IdentityEvidenceKind {
        #[serde(rename = "access_token")]
        AccessToken,
        #[serde(rename = "saml_assertion")]
        SamlAssertion,
        #[serde(rename = "ticket")]
        Ticket,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IdentityEvidence {
        pub kind: IdentityEvidenceKind,
        pub value: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum IdentityHeaderClaim {
        #[serde(rename = "sub")]
        Sub,
        #[serde(rename = "username")]
        Username,
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "name")]
        Name,
        #[serde(rename = "given_name")]
        GivenName,
        #[serde(rename = "family_name")]
        FamilyName,
        #[serde(rename = "groups")]
        Groups,
        #[serde(rename = "mechanism")]
        Mechanism,
        #[serde(rename = "acr")]
        Acr,
        #[serde(rename = "amr")]
        Amr,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IdentityHeader {
        /// An HTTP token, not a reserved header.
        pub name: String,
        pub claim: IdentityHeaderClaim,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum IdentityRequestClaimsItem {
        #[serde(rename = "sub")]
        Sub,
        #[serde(rename = "username")]
        Username,
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "name")]
        Name,
        #[serde(rename = "given_name")]
        GivenName,
        #[serde(rename = "family_name")]
        FamilyName,
        #[serde(rename = "groups")]
        Groups,
        #[serde(rename = "mechanism")]
        Mechanism,
        #[serde(rename = "acr")]
        Acr,
        #[serde(rename = "amr")]
        Amr,
    }

    /// Closed: any other member is 400 STS-XACML-0229.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IdentityRequest {
        /// A non-public route of this PEP's own proxy document.
        pub route: String,
        pub evidence: crate::pep_control_plane::components::IdentityEvidence,
        /// headers mode only: claims the route's headers name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Vec<IdentityRequestClaimsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IntrospectRequest {
        pub token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum IntrospectionAud {
        V1(Vec<String>),
        String(String),
    }

    /// active false alone, or active true with the RFC 7662 members that are not
    /// null.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Introspection {
        pub active: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub aud: Option<IntrospectionAud>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iss: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exp: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iat: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub token_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cnf: Option<serde_json::Map<String, serde_json::Value>>,
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
    pub struct ListenerCertificate {
        pub pep: String,
        pub listener: String,
        pub renew: i64,
        /// False when the certificate held was answered again.
        pub issued: bool,
        #[serde(rename = "serialHex")]
        pub serial_hex: String,
        #[serde(rename = "notBefore")]
        pub not_before: String,
        #[serde(rename = "notAfter")]
        pub not_after: String,
        #[serde(rename = "replacedSerialHex")]
        pub replaced_serial_hex: Option<String>,
        #[serde(rename = "certificatePem")]
        pub certificate_pem: String,
        /// Leaf to Root, each PEM ending in a newline: the one member the PEP
        /// reads.
        #[serde(rename = "fullChainPem")]
        pub full_chain_pem: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ListenerCertificateRequest {
        /// A defined https listener of this PEP.
        pub listener: String,
        /// PKCS #10, PEM or base64 DER; its key one of the listener's keyAlg
        /// values.
        pub csr: String,
        /// Read only when no certificate was presented; the PEP does not send it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ListenerDefinitionProtocol {
        #[serde(rename = "http")]
        Http,
        #[serde(rename = "https")]
        Https,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ListenerDefinitionPurpose {
        #[serde(rename = "api")]
        Api,
        #[serde(rename = "proxy")]
        Proxy,
    }

    /// https only.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ListenerDefinitionKeyAlg {
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ListenerDefinition {
        /// Not one of the four environment listeners' ids.
        pub id: String,
        pub protocol: ListenerDefinitionProtocol,
        pub purpose: ListenerDefinitionPurpose,
        /// An IP literal.
        pub address: String,
        pub port: i64,
        #[serde(rename = "dnsNames")]
        pub dns_names: Vec<String>,
        #[serde(rename = "ipAddresses")]
        pub ip_addresses: Vec<String>,
        /// https only.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<ListenerDefinitionKeyAlg>,
        pub renew: i64,
        /// The tuning in force, complete.
        pub tuning: crate::pep_control_plane::components::ListenerTuning,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ListenerPool {
        pub min: i64,
        pub max: i64,
        pub current: i64,
        pub busy: i64,
        pub idle: i64,
        pub queued: i64,
        pub completed: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ListenerStats {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accepted: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub open: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http1: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http2: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handshakes: Option<i64>,
        #[serde(rename = "handshakeFailures", default, skip_serializing_if = "Option::is_none")]
        pub handshake_failures: Option<i64>,
        /// Kept only with all seven members.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pool: Option<crate::pep_control_plane::components::ListenerPool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ListenerTuningMinVersion {
        #[serde(rename = "TLSv1")]
        TlSv1,
        #[serde(rename = "TLSv1.1")]
        TlSv11,
        #[serde(rename = "TLSv1.2")]
        TlSv12,
        #[serde(rename = "TLSv1.3")]
        TlSv13,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ListenerTuning {
        #[serde(rename = "minVersion")]
        pub min_version: ListenerTuningMinVersion,
        #[serde(rename = "disableTls12")]
        pub disable_tls12: bool,
        pub ciphers: String,
        #[serde(rename = "tls13CipherSuites")]
        pub tls13_cipher_suites: String,
        #[serde(rename = "pqcOnly")]
        pub pqc_only: bool,
        pub groups: String,
        #[serde(rename = "signatureAlgorithms")]
        pub signature_algorithms: String,
        #[serde(rename = "trustAnchorsFile")]
        pub trust_anchors_file: String,
        #[serde(rename = "trustIssuedClientCertificates")]
        pub trust_issued_client_certificates: bool,
        #[serde(rename = "askClientCertificate")]
        pub ask_client_certificate: bool,
        #[serde(rename = "requireClientCertificate")]
        pub require_client_certificate: bool,
        #[serde(rename = "sessionTimeoutS")]
        pub session_timeout_s: i64,
        #[serde(rename = "sessionCacheSize")]
        pub session_cache_size: i64,
        #[serde(rename = "keepAliveTimeoutS")]
        pub keep_alive_timeout_s: i64,
        #[serde(rename = "headersTimeoutS")]
        pub headers_timeout_s: i64,
        #[serde(rename = "maxRequestsPerSocket")]
        pub max_requests_per_socket: i64,
        #[serde(rename = "maxConnections")]
        pub max_connections: i64,
        pub http2: bool,
        #[serde(rename = "http2MaxConcurrentStreams")]
        pub http2_max_concurrent_streams: i64,
        #[serde(rename = "threadPoolMin")]
        pub thread_pool_min: i64,
        #[serde(rename = "threadPoolMax")]
        pub thread_pool_max: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ListenersReport {
        pub listeners: Vec<crate::pep_control_plane::components::ReportedListener>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub memory: Option<crate::pep_control_plane::components::ProcessMemory>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<Vec<crate::pep_control_plane::components::PathCount>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ManagedSettingsBias {
        #[serde(rename = "deny-biased")]
        DenyBiased,
        #[serde(rename = "permit-biased")]
        PermitBiased,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ManagedSettingsLogLevel {
        #[serde(rename = "trace")]
        Trace,
        #[serde(rename = "debug")]
        Debug,
        #[serde(rename = "info")]
        Info,
        #[serde(rename = "warn")]
        Warn,
        #[serde(rename = "error")]
        Error,
        #[serde(rename = "fatal")]
        Fatal,
    }

    /// Only the keys an administrator set. A notifyUrl that is not https is held
    /// and refused by the PEP.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ManagedSettings {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(rename = "notifyUrl", default, skip_serializing_if = "Option::is_none")]
        pub notify_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bias: Option<ManagedSettingsBias>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pip: Option<bool>,
        #[serde(rename = "pollIntervalMs", default, skip_serializing_if = "Option::is_none")]
        pub poll_interval_ms: Option<i64>,
        #[serde(rename = "heartbeatIntervalMs", default, skip_serializing_if = "Option::is_none")]
        pub heartbeat_interval_ms: Option<i64>,
        #[serde(rename = "backoffMaxMs", default, skip_serializing_if = "Option::is_none")]
        pub backoff_max_ms: Option<i64>,
        #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub timeout_ms: Option<i64>,
        #[serde(rename = "maxBodyBytes", default, skip_serializing_if = "Option::is_none")]
        pub max_body_bytes: Option<i64>,
        #[serde(rename = "httpsReloadIntervalMs", default, skip_serializing_if = "Option::is_none")]
        pub https_reload_interval_ms: Option<i64>,
        #[serde(rename = "logLevel", default, skip_serializing_if = "Option::is_none")]
        pub log_level: Option<ManagedSettingsLogLevel>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authzen: Option<bool>,
        /// An https origin.
        #[serde(rename = "authzenPdpIdentifier", default, skip_serializing_if = "Option::is_none")]
        pub authzen_pdp_identifier: Option<String>,
        #[serde(rename = "authzenForwardTimeoutMs", default, skip_serializing_if = "Option::is_none")]
        pub authzen_forward_timeout_ms: Option<i64>,
        #[serde(rename = "proxySessionRecheckMs", default, skip_serializing_if = "Option::is_none")]
        pub proxy_session_recheck_ms: Option<i64>,
        #[serde(rename = "proxySessionTtlMs", default, skip_serializing_if = "Option::is_none")]
        pub proxy_session_ttl_ms: Option<i64>,
        #[serde(rename = "proxyMaxSessions", default, skip_serializing_if = "Option::is_none")]
        pub proxy_max_sessions: Option<i64>,
        #[serde(rename = "proxyMaxAccounts", default, skip_serializing_if = "Option::is_none")]
        pub proxy_max_accounts: Option<i64>,
        #[serde(rename = "proxyJwksTtlMs", default, skip_serializing_if = "Option::is_none")]
        pub proxy_jwks_ttl_ms: Option<i64>,
        /// Refused true in product mode.
        #[serde(rename = "proxyUpstreamInsecure", default, skip_serializing_if = "Option::is_none")]
        pub proxy_upstream_insecure: Option<bool>,
        /// Refused true in product mode.
        #[serde(rename = "proxyRpAllowInsecure", default, skip_serializing_if = "Option::is_none")]
        pub proxy_rp_allow_insecure: Option<bool>,
        #[serde(rename = "proxySignalsPollMs", default, skip_serializing_if = "Option::is_none")]
        pub proxy_signals_poll_ms: Option<i64>,
        #[serde(rename = "proxySignalsStaleMs", default, skip_serializing_if = "Option::is_none")]
        pub proxy_signals_stale_ms: Option<i64>,
        #[serde(rename = "proxyStripCookies", default, skip_serializing_if = "Option::is_none")]
        pub proxy_strip_cookies: Option<String>,
        /// PEP_AUDIT: whether this PEP sends its decision records to the service's
        /// audit log (#1827).
        #[serde(rename = "auditEnabled", default, skip_serializing_if = "Option::is_none")]
        pub audit_enabled: Option<bool>,
        #[serde(rename = "auditIntervalMs", default, skip_serializing_if = "Option::is_none")]
        pub audit_interval_ms: Option<i64>,
        #[serde(rename = "auditBatch", default, skip_serializing_if = "Option::is_none")]
        pub audit_batch: Option<i64>,
        #[serde(rename = "auditBuffer", default, skip_serializing_if = "Option::is_none")]
        pub audit_buffer: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PathCount {
        pub method: String,
        /// The path, its query cut.
        pub path: String,
        pub count: i64,
        pub refused: i64,
    }

    /// The reverse proxy's CAEP and RISC receivers: counts only; the service drops
    /// a member it does not name.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PepSignals {
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
        pub library_sessions: crate::pep_control_plane::components::LibrarySessions,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub streams: Option<Vec<crate::pep_control_plane::components::SignalStream>>,
    }

    pub type PipError = String;

    pub type PipRequest = String;

    pub type PipResponse = String;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum PolicyRowKind {
        #[serde(rename = "Policy")]
        Policy,
        #[serde(rename = "PolicySet")]
        PolicySet,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PolicyRow {
        pub name: String,
        #[serde(rename = "policyId")]
        pub policy_id: String,
        pub kind: PolicyRowKind,
        pub version: String,
        #[serde(rename = "combiningAlgId")]
        pub combining_alg_id: String,
        #[serde(rename = "isRoot")]
        pub is_root: bool,
        pub description: String,
        /// The XACML 3.0 Policy or PolicySet, as XML.
        pub document: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PolicySet {
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        /// The root policy's name. Not read by the PEP, which uses isRoot.
        pub root: Option<String>,
        /// Only when root is null.
        #[serde(rename = "rootNote", default, skip_serializing_if = "Option::is_none")]
        pub root_note: Option<String>,
        /// Every enabled policy but those withheld.
        pub policies: Vec<crate::pep_control_plane::components::PolicyRow>,
        /// Names withheld from PEPs: the access and issuance policies and every
        /// policy an application owns.
        pub withheld: Vec<String>,
        pub note: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProcessMemory {
        #[serde(rename = "rssBytes", default, skip_serializing_if = "Option::is_none")]
        pub rss_bytes: Option<i64>,
        #[serde(rename = "virtualBytes", default, skip_serializing_if = "Option::is_none")]
        pub virtual_bytes: Option<i64>,
        #[serde(rename = "dataBytes", default, skip_serializing_if = "Option::is_none")]
        pub data_bytes: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub threads: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyDocument {
        pub enabled: bool,
        /// An absolute http(s) URL with no userinfo, query or fragment.
        pub upstream: String,
        /// An origin or empty; https when any route uses session.
        #[serde(rename = "publicBaseUrl")]
        pub public_base_url: String,
        #[serde(rename = "upstreamTimeoutMs")]
        pub upstream_timeout_ms: i64,
        #[serde(rename = "maxBodyBytes")]
        pub max_body_bytes: i64,
        pub routes: Vec<crate::pep_control_plane::components::ProxyRoute>,
    }

    /// configured false: note alone. configured true: proxy, realm and validation.
    /// A cluster member gets its cluster's document.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyPull {
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        pub pep: String,
        pub configured: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub proxy: Option<crate::pep_control_plane::components::ProxyDocument>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<crate::pep_control_plane::components::RealmFacts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub validation: Option<crate::pep_control_plane::components::ValidationUrls>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ProxyRouteMatch {
        #[serde(rename = "prefix")]
        Prefix,
        #[serde(rename = "exact")]
        Exact,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ProxyRouteMethodsItem {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "HEAD")]
        Head,
        #[serde(rename = "POST")]
        Post,
        #[serde(rename = "PUT")]
        Put,
        #[serde(rename = "PATCH")]
        Patch,
        #[serde(rename = "DELETE")]
        Delete,
        #[serde(rename = "OPTIONS")]
        Options,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ProxyRouteMechanismsItem {
        #[serde(rename = "session")]
        Session,
        #[serde(rename = "oauth2")]
        Oauth2,
        #[serde(rename = "saml2")]
        Saml2,
        #[serde(rename = "basic")]
        Basic,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyRoute {
        pub id: String,
        /// Never /.iya-pep or under /.iya-pep/, which the proxy keeps
        /// (STS-XACML-0300 at the save; a stored one makes the pull configured:
        /// false).
        pub path: String,
        #[serde(rename = "match")]
        pub match_: ProxyRouteMatch,
        /// Empty denies every method.
        pub methods: Vec<ProxyRouteMethodsItem>,
        pub mechanisms: Vec<ProxyRouteMechanismsItem>,
        /// Empty on a public route.
        pub application: String,
        pub authorization: crate::pep_control_plane::components::RouteAuthorization,
        pub identity: crate::pep_control_plane::components::RouteIdentity,
        #[serde(rename = "forwardCredentials")]
        pub forward_credentials: bool,
        pub signals: bool,
        /// Only with session.
        #[serde(rename = "multipleAccounts")]
        pub multiple_accounts: bool,
        pub resolved: crate::pep_control_plane::components::RouteResolution,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RealmFacts {
        pub issuer: String,
        #[serde(rename = "jwksUri")]
        pub jwks_uri: String,
        /// Not read: the PEP discovers it from issuer.
        #[serde(rename = "authorizationEndpoint")]
        pub authorization_endpoint: String,
        /// Not read: the PEP discovers it from issuer.
        #[serde(rename = "tokenEndpoint")]
        pub token_endpoint: String,
        /// Not read: the PEP discovers it from issuer.
        #[serde(rename = "endSessionEndpoint")]
        pub end_session_endpoint: String,
        #[serde(rename = "samlIssuer")]
        pub saml_issuer: String,
        /// PEM certificates.
        #[serde(rename = "signingCertificates")]
        pub signing_certificates: Vec<String>,
        /// PEM, leaf to Root.
        #[serde(rename = "tlsCaChain")]
        pub tls_ca_chain: String,
        /// By client id: each session route's client.
        pub clients: serde_json::Map<String, serde_json::Value>,
        /// Cookies of the service's the proxy strips upstream; absent or null is
        /// the built-in list.
        #[serde(rename = "serviceCookiePrefixes", default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub service_cookie_prefixes: Option<Option<Vec<String>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RegisterNotify {
        pub url: Option<String>,
        pub usable: bool,
        pub why: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RegisterRequestBias {
        #[serde(rename = "deny-biased")]
        DenyBiased,
        #[serde(rename = "permit-biased")]
        PermitBiased,
    }

    /// container (the xacml-pep image) or embedded (a PEP inside an authentication
    /// library, #2026). Absent is container, so an older PEP is one. Anything else
    /// is 400 STS-XACML-0342.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RegisterRequestKind {
        #[serde(rename = "container")]
        Container,
        #[serde(rename = "embedded")]
        Embedded,
    }

    /// An embedded PEP's mode: central (every decision asked of POST
    /// /access/v1/evaluation) or local (the bound application's policies pulled and
    /// decided in process). Required for an embedded PEP (400 STS-XACML-0342
    /// otherwise); with a container it is 400 STS-XACML-0341.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RegisterRequestMode {
        #[serde(rename = "central")]
        Central,
        #[serde(rename = "local")]
        Local,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RegisterRequest {
        /// PEP_NAME. Read only when no certificate was presented.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Where the service nudges this PEP: https, or empty. notify_url is
        /// accepted as an alias.
        #[serde(rename = "notifyUrl", default, skip_serializing_if = "Option::is_none")]
        pub notify_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bias: Option<RegisterRequestBias>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
        /// Empty keeps the description held.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Sent only when the PEP knows it: a lower-case DNS name of at most 253
        /// characters, not an IP address; anything else is 400 STS-XACML-0261.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub hostname: Option<Option<String>>,
        /// container (the xacml-pep image) or embedded (a PEP inside an
        /// authentication library, #2026). Absent is container, so an older PEP is
        /// one. Anything else is 400 STS-XACML-0342.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<RegisterRequestKind>,
        /// An embedded PEP's application: its identifier in the realm's registry.
        /// It must be the application the PEP's entry is bound to
        /// (stsPepApplication): bound to none is 403 STS-XACML-0338, another or
        /// none named 403 STS-XACML-0339. Ignored for a container.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub application: Option<String>,
        /// An embedded PEP's mode: central (every decision asked of POST
        /// /access/v1/evaluation) or local (the bound application's policies pulled
        /// and decided in process). Required for an embedded PEP (400
        /// STS-XACML-0342 otherwise); with a container it is 400 STS-XACML-0341.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mode: Option<RegisterRequestMode>,
        /// The PEP protocol version the PEP's package speaks. The service supports
        /// 1; any other, or none from an embedded PEP, is 400 STS-XACML-0340.
        #[serde(rename = "protocolVersion", default, skip_serializing_if = "Option::is_none")]
        pub protocol_version: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Registered {
        pub registered: bool,
        pub name: String,
        pub created: bool,
        /// A certificate was presented.
        pub authenticated: bool,
        pub verified: bool,
        #[serde(rename = "verifiedWhy")]
        pub verified_why: String,
        /// The certificate's DN, or empty.
        pub identity: String,
        /// The policy repository's token. Not read by the PEP.
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        #[serde(rename = "policiesUrl")]
        pub policies_url: String,
        #[serde(rename = "heartbeatUrl")]
        pub heartbeat_url: String,
        pub notify: crate::pep_control_plane::components::RegisterNotify,
        pub note: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReportedCertificate {
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
    pub enum ReportedListenerSource {
        #[serde(rename = "environment")]
        Environment,
        #[serde(rename = "service")]
        Service,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ReportedListenerProtocol {
        #[serde(rename = "http")]
        Http,
        #[serde(rename = "https")]
        Https,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ReportedListenerPurpose {
        #[serde(rename = "api")]
        Api,
        #[serde(rename = "proxy")]
        Proxy,
        #[serde(rename = "crl")]
        Crl,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ReportedListenerState {
        #[serde(rename = "listening")]
        Listening,
        #[serde(rename = "waiting")]
        Waiting,
        #[serde(rename = "failed")]
        Failed,
        #[serde(rename = "off")]
        Off,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum ReportedListenerReason {
        #[serde(rename = "none")]
        None,
        #[serde(rename = "address-in-use")]
        AddressInUse,
        #[serde(rename = "permission-denied")]
        PermissionDenied,
        #[serde(rename = "address-unavailable")]
        AddressUnavailable,
        #[serde(rename = "no-certificate")]
        NoCertificate,
        #[serde(rename = "certificate-refused")]
        CertificateRefused,
        #[serde(rename = "certificate-request-refused")]
        CertificateRequestRefused,
        #[serde(rename = "proxy-off")]
        ProxyOff,
        #[serde(rename = "http-off")]
        HttpOff,
        #[serde(rename = "not-configured")]
        NotConfigured,
        #[serde(rename = "crl-only")]
        CrlOnly,
        #[serde(rename = "other")]
        Other,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReportedListener {
        pub id: String,
        pub source: ReportedListenerSource,
        pub protocol: ReportedListenerProtocol,
        pub purpose: ReportedListenerPurpose,
        pub address: String,
        pub port: i64,
        pub state: ReportedListenerState,
        pub reason: ReportedListenerReason,
        pub renew: i64,
        pub certificate: Option<crate::pep_control_plane::components::ReportedCertificate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stats: Option<crate::pep_control_plane::components::ListenerStats>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RouteAuthorizationKind {
        #[serde(rename = "policy")]
        Policy,
        #[serde(rename = "simple")]
        Simple,
        #[serde(rename = "public")]
        Public,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RouteAuthorizationActionModel {
        #[serde(rename = "method")]
        Method,
        #[serde(rename = "crud")]
        Crud,
        #[serde(rename = "read-write")]
        ReadWrite,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RouteAuthorization {
        pub kind: RouteAuthorizationKind,
        pub policy: String,
        /// Empty: the normalised path.
        pub resource: String,
        #[serde(rename = "actionModel")]
        pub action_model: RouteAuthorizationActionModel,
        /// The roles each action of the model needs, at most 8 each: create, read,
        /// update, delete for crud; read, write for read-write.
        pub roles: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum RouteIdentityMode {
        #[serde(rename = "headers")]
        Headers,
        #[serde(rename = "saml")]
        Saml,
        #[serde(rename = "jwt")]
        Jwt,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RouteIdentity {
        pub mode: RouteIdentityMode,
        pub headers: Vec<crate::pep_control_plane::components::IdentityHeader>,
        pub separator: String,
    }

    /// What the service resolved for a route. When not usable, why and code
    /// (STS-XACML-0217 to 0223, 0228: the one error code this surface sends).
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RouteResolution {
        pub usable: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        /// An oauth2 route's accepted audiences.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub audiences: Option<Vec<String>>,
        #[serde(rename = "samlAudience", default, skip_serializing_if = "Option::is_none")]
        pub saml_audience: Option<String>,
        /// A session route's client.
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SamlRequest {
        /// The assertion's XML, base64; at most 262144 bytes decoded.
        pub assertion: String,
        /// The route's resolved.samlAudience.
        pub audience: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    /// valid false alone (the reason audited: STS-XACML-0208 to 0213), or valid
    /// true with the assertion's subject and its facts.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SamlValidation {
        pub valid: bool,
        /// The NameID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(rename = "notOnOrAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_on_or_after: Option<String>,
        #[serde(rename = "sessionIndex", default, skip_serializing_if = "Option::is_none")]
        pub session_index: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum SessionClientTokenEndpointAuthMethod {
        #[serde(rename = "client_secret_basic")]
        ClientSecretBasic,
        #[serde(rename = "client_secret_post")]
        ClientSecretPost,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SessionClient {
        /// The application client's secret, in the clear: the PEP is its relying
        /// party.
        #[serde(rename = "clientSecret")]
        pub client_secret: String,
        #[serde(rename = "tokenEndpointAuthMethod")]
        pub token_endpoint_auth_method: SessionClientTokenEndpointAuthMethod,
        #[serde(rename = "redirectUri")]
        pub redirect_uri: String,
        pub scopes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SessionLiveness {
        pub live: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        /// Only when it differs from username.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SessionRequest {
        pub sid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum SettingInUseSource {
        #[serde(rename = "service")]
        Service,
        #[serde(rename = "environment")]
        Environment,
        #[serde(rename = "derived")]
        Derived,
        #[serde(rename = "default")]
        Default,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SettingInUse {
        pub value: crate::unions::BoolOrIntegerOrString,
        pub source: SettingInUseSource,
        /// Only on notifyUrl, when the one set was not https.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rejected: Option<bool>,
    }

    /// configured false: note; configured true: settings. listeners only when at
    /// least one is defined; environmentTuning always, unless the stored listeners
    /// failed validation (STS-XACML-0252), when neither is sent.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SettingsPull {
        #[serde(rename = "syncToken")]
        pub sync_token: String,
        /// Not read by the PEP.
        pub pep: String,
        pub configured: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<crate::pep_control_plane::components::ManagedSettings>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::double_option")]
        pub listeners: Option<Option<Vec<crate::pep_control_plane::components::ListenerDefinition>>>,
        #[serde(rename = "environmentTuning", default, skip_serializing_if = "Option::is_none")]
        pub environment_tuning: Option<crate::pep_control_plane::components::EnvironmentTuning>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SettingsReport {
        pub token: String,
        /// Every managed setting in force, by key; values are checked against the
        /// row and unknown keys dropped.
        pub values: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignalStream {
        #[serde(rename = "clientId")]
        pub client_id: String,
        #[serde(rename = "streamId")]
        pub stream_id: String,
        pub running: bool,
        pub healthy: bool,
        #[serde(rename = "startedAgeMs")]
        pub started_age_ms: Option<i64>,
        #[serde(rename = "lastPollAgeMs")]
        pub last_poll_age_ms: Option<i64>,
        #[serde(rename = "lastSuccessAgeMs")]
        pub last_success_age_ms: Option<i64>,
        #[serde(rename = "consecutiveFailures")]
        pub consecutive_failures: i64,
        pub polls: i64,
        #[serde(rename = "failedPolls")]
        pub failed_polls: i64,
        #[serde(rename = "setsAccepted")]
        pub sets_accepted: i64,
        #[serde(rename = "setsRefused")]
        pub sets_refused: i64,
        #[serde(rename = "sessionsEnded")]
        pub sessions_ended: i64,
    }

    /// A refusal for now, from every validation door: the doors' shared limiter
    /// (STS-XACML-0215), or basic's lockout of the account (0205). The wait is
    /// retryAfterS, and the Retry-After header.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TooManyRequests {
        pub error: String,
        pub error_description: String,
        #[serde(rename = "retryAfterS")]
        pub retry_after_s: i64,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ValidationUrls {
        pub introspect: String,
        pub basic: String,
        pub saml: String,
        pub session: String,
        pub identity: String,
    }

}

/// Pull who may ask the AuthZEN edge PDP
pub mod get_authzen_callers {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/xacml/pep/authzen-callers";
    pub const OPERATION_ID: &str = "getAuthzenCallers";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
    }

    pub type Answer200 = crate::pep_control_plane::components::AuthzenCallers;
}

/// Pull the realm's AuthZEN attribute catalogue
pub mod get_authzen_catalogue {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/xacml/pep/authzen-catalogue";
    pub const OPERATION_ID: &str = "getAuthzenCatalogue";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
    }

    pub type Answer200 = crate::pep_control_plane::components::AuthzenCatalogue;
}

/// Validation door: a username and password
pub mod post_basic {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/basic";
    pub const OPERATION_ID: &str = "postBasic";

    pub type Body = crate::pep_control_plane::components::BasicRequest;

    pub type Answer200 = crate::pep_control_plane::components::BasicValidation;
}

/// Report what this PEP holds and does
pub mod post_heartbeat {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/heartbeat";
    pub const OPERATION_ID: &str = "postHeartbeat";

    pub type Body = crate::pep_control_plane::components::HeartbeatRequest;

    pub type Answer200 = crate::pep_control_plane::components::HeartbeatAnswer;
}

/// Validation door: the identity to deliver upstream
pub mod post_identity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/identity";
    pub const OPERATION_ID: &str = "postIdentity";

    pub type Body = crate::pep_control_plane::components::IdentityRequest;

    pub type Answer200 = crate::pep_control_plane::components::IdentityAnswer;
}

/// Validation door: an access token (RFC 7662)
pub mod post_introspect {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/introspect";
    pub const OPERATION_ID: &str = "postIntrospect";

    pub type Body = crate::pep_control_plane::components::IntrospectRequest;

    pub type Answer200 = crate::pep_control_plane::components::Introspection;
}

/// Have a defined HTTPS listener's certificate issued
pub mod post_listener_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/listener-certificate";
    pub const OPERATION_ID: &str = "postListenerCertificate";

    pub type Body = crate::pep_control_plane::components::ListenerCertificateRequest;

    pub type Answer200 = crate::pep_control_plane::components::ListenerCertificate;
}

/// Pull the policy repository
pub mod get_policies {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/xacml/pep/policies";
    pub const OPERATION_ID: &str = "getPolicies";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pep: Option<String>,
    }

    pub type Answer200 = crate::pep_control_plane::components::PolicySet;
}

/// Pull the reverse proxy's configuration
pub mod get_proxy {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/xacml/pep/proxy";
    pub const OPERATION_ID: &str = "getProxy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    pub type Answer200 = crate::pep_control_plane::components::ProxyPull;
}

/// Register, or register again
pub mod post_register {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/register";
    pub const OPERATION_ID: &str = "postRegister";

    pub type Body = crate::pep_control_plane::components::RegisterRequest;

    pub type Answer200 = crate::pep_control_plane::components::Registered;

    pub type Answer201 = crate::pep_control_plane::components::Registered;
}

/// Validation door: a SAML 2.0 assertion
pub mod post_saml {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/saml";
    pub const OPERATION_ID: &str = "postSaml";

    pub type Body = crate::pep_control_plane::components::SamlRequest;

    pub type Answer200 = crate::pep_control_plane::components::SamlValidation;
}

/// Validation door: is a sign-on session live
pub mod post_session {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pep/session";
    pub const OPERATION_ID: &str = "postSession";

    pub type Body = crate::pep_control_plane::components::SessionRequest;

    pub type Answer200 = crate::pep_control_plane::components::SessionLiveness;
}

/// Pull the managed settings and listeners
pub mod get_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/xacml/pep/settings";
    pub const OPERATION_ID: &str = "getSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    pub type Answer200 = crate::pep_control_plane::components::SettingsPull;
}

/// The policy information point
pub mod post_pip {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/xacml/pip";
    pub const OPERATION_ID: &str = "postPip";

    /// The body is not JSON (an upload): its bytes.
    pub type Body = Vec<u8>;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "postBasic" => Some(serde_json::from_value::<post_basic::Body>(value.clone()).map(|_| ())),
        "postHeartbeat" => Some(serde_json::from_value::<post_heartbeat::Body>(value.clone()).map(|_| ())),
        "postIdentity" => Some(serde_json::from_value::<post_identity::Body>(value.clone()).map(|_| ())),
        "postIntrospect" => Some(serde_json::from_value::<post_introspect::Body>(value.clone()).map(|_| ())),
        "postListenerCertificate" => Some(serde_json::from_value::<post_listener_certificate::Body>(value.clone()).map(|_| ())),
        "postRegister" => Some(serde_json::from_value::<post_register::Body>(value.clone()).map(|_| ())),
        "postSaml" => Some(serde_json::from_value::<post_saml::Body>(value.clone()).map(|_| ())),
        "postSession" => Some(serde_json::from_value::<post_session::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getAuthzenCallers", 200) => Some(serde_json::from_value::<get_authzen_callers::Answer200>(value.clone()).map(|_| ())),
        ("getAuthzenCatalogue", 200) => Some(serde_json::from_value::<get_authzen_catalogue::Answer200>(value.clone()).map(|_| ())),
        ("postBasic", 200) => Some(serde_json::from_value::<post_basic::Answer200>(value.clone()).map(|_| ())),
        ("postHeartbeat", 200) => Some(serde_json::from_value::<post_heartbeat::Answer200>(value.clone()).map(|_| ())),
        ("postIdentity", 200) => Some(serde_json::from_value::<post_identity::Answer200>(value.clone()).map(|_| ())),
        ("postIntrospect", 200) => Some(serde_json::from_value::<post_introspect::Answer200>(value.clone()).map(|_| ())),
        ("postListenerCertificate", 200) => Some(serde_json::from_value::<post_listener_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getPolicies", 200) => Some(serde_json::from_value::<get_policies::Answer200>(value.clone()).map(|_| ())),
        ("getProxy", 200) => Some(serde_json::from_value::<get_proxy::Answer200>(value.clone()).map(|_| ())),
        ("postRegister", 200) => Some(serde_json::from_value::<post_register::Answer200>(value.clone()).map(|_| ())),
        ("postRegister", 201) => Some(serde_json::from_value::<post_register::Answer201>(value.clone()).map(|_| ())),
        ("postSaml", 200) => Some(serde_json::from_value::<post_saml::Answer200>(value.clone()).map(|_| ())),
        ("postSession", 200) => Some(serde_json::from_value::<post_session::Answer200>(value.clone()).map(|_| ())),
        ("getSettings", 200) => Some(serde_json::from_value::<get_settings::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
