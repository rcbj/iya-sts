// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// The service Root the chain ends at, which every realm of this service
/// shares.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExportIssuingCaRoot {
    pub subject: String,
    /// Its SHA-256 fingerprint, upper-case hex with no colons.
    pub fingerprint256: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExportIssuingCa {
    /// The Issuing CA's subject, as RFC 4514 writes it.
    pub subject: String,
    /// Its issuer: this realm's Intermediate.
    pub issuer: String,
    /// Its serial number, lower-case hex.
    #[serde(rename = "serialHex")]
    pub serial_hex: String,
    /// Valid from, ISO 8601.
    #[serde(rename = "notBefore")]
    pub not_before: String,
    /// Valid until, ISO 8601.
    #[serde(rename = "notAfter")]
    pub not_after: String,
    /// The CA's own key algorithm.
    #[serde(rename = "keyAlg")]
    pub key_alg: String,
    /// What the CA signs the export signer's certificate with.
    #[serde(rename = "signatureAlg")]
    pub signature_alg: String,
    /// The SHA-256 fingerprint of the certificate's DER, upper-case hex with no
    /// colons: what an administrator in another realm names in
    /// `issuerFingerprint` to trust this realm's exports, and what an
    /// inspection of an export answers as `issuerFingerprint`.
    pub fingerprint256: String,
    /// The same digest as RFC 7515 section 4.1.8's `x5t#S256`: base64url,
    /// unpadded.
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
    /// The Issuing CA's certificate, PEM. The second certificate of every
    /// export's `x5c`.
    #[serde(rename = "certificatePem")]
    pub certificate_pem: String,
    /// The chain up to but not including the service Root, PEM, the Issuing CA
    /// first and then this realm's Intermediate.
    #[serde(rename = "chainPem")]
    pub chain_pem: Vec<String>,
    /// The service Root the chain ends at, which every realm of this service
    /// shares.
    pub root: PolicyExportIssuingCaRoot,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExportable {
    /// The policy's kind.
    pub kind: String,
    /// Its name within its kind.
    pub name: String,
    /// True for one of the authentication policy's named policies.
    pub named: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelection {
    /// The policy's kind, an id of Directory → Policies: `password`, `authn`,
    /// `passkey` and the others.
    pub kind: String,
    /// The policy's name within its kind: `default`, a named policy, or one of
    /// the authentication policy's named policies.
    pub name: String,
}

/// `own`: signed under this realm's own Policy Export Signing CA, trusted.
/// `trusted`: another realm's, whose chain this realm's signer truststore holds
/// for policy-signer. `foreign`: another realm's this realm has not trusted, so
/// an import needs an administrator's yes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PolicyTransferAnswerOrigin {
    #[serde(rename = "own")]
    Own,
    #[serde(rename = "trusted")]
    Trusted,
    #[serde(rename = "foreign")]
    Foreign,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTransferAnswer {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    /// The signed export: a JWS in the flattened JSON serialization (RFC 7515
    /// section 7.2.2), its protected header carrying `typ` policy-export+json
    /// and the signer's whole chain in `x5c`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<crate::PolicyTransferValue>,
    /// A name to save the export under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// The export as a file to save, `{ name, mime, base64 }`: the same
    /// document, which the console saves where it was asked from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<crate::PolicyTransferValue>>,
    /// The signing certificate: for an export its subject, algorithm, serial
    /// and expiry; for an inspection or import its subject, issuer, validity
    /// and SHA-256 fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<crate::PolicyTransferValue>,
    /// How many profiles of each kind the export carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    /// `own`: signed under this realm's own Policy Export Signing CA, trusted.
    /// `trusted`: another realm's, whose chain this realm's signer truststore
    /// holds for policy-signer. `foreign`: another realm's this realm has not
    /// trusted, so an import needs an administrator's yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<PolicyTransferAnswerOrigin>,
    /// Whether the signer is trusted without a question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    /// The JWS algorithm the export was signed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Each certificate of the signer's chain, leaf first, Root last: subject,
    /// issuer, validity and SHA-256 fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<crate::PolicyTransferValue>>,
    /// The SHA-256 fingerprint of the chain's Issuing CA, which an import of a
    /// foreign export names in `issuerFingerprint` to say yes.
    #[serde(rename = "issuerFingerprint", default, skip_serializing_if = "Option::is_none")]
    pub issuer_fingerprint: Option<String>,
    /// The realm the export says it came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// That realm's DNS domain.
    #[serde(rename = "realmDomain", default, skip_serializing_if = "Option::is_none")]
    pub realm_domain: Option<String>,
    /// When it was exported.
    #[serde(rename = "exportedAt", default, skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<String>,
    /// Who exported it.
    #[serde(rename = "exportedBy", default, skip_serializing_if = "Option::is_none")]
    pub exported_by: Option<String>,
    /// The kinds of policy the export carries, each with its profile names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<crate::PolicyTransferValue>>,
    /// The validation door's verdict on the chain, purpose policy-signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<crate::PolicyTransferValue>,
    /// An import: the profiles written, by kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<Vec<crate::PolicyTransferValue>>,
    /// An import: each profile its kind refused, with the kind's code and
    /// sentences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Vec<crate::PolicyTransferValue>>,
    /// An import: the certificates added to this realm's signer truststore by
    /// the yes.
    #[serde(rename = "trustAdded", default, skip_serializing_if = "Option::is_none")]
    pub trust_added: Option<Vec<crate::PolicyTransferValue>>,
    /// An import of another realm's export that was not confirmed: ask, then
    /// post again with `trustSigner` and `issuerFingerprint`.
    #[serde(rename = "needsTrust", default, skip_serializing_if = "Option::is_none")]
    pub needs_trust: Option<bool>,
    /// With `needsTrust`: what the question is about, as `inspect` answers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<crate::PolicyTransferValue>,
    /// An inspection: every profile the export carries, with whether this realm
    /// already stores one by that name (`replaces`). What an import's
    /// `policies` names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<crate::PolicyTransferProfile>>,
    /// The policies a selection named: for an export or an import the
    /// `policies` it was asked for, for an inspection the selection the
    /// document records it was exported as. Absent for a whole export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<Vec<crate::PolicySelection>>,
    /// A refused selection: the policies it named that this realm does not
    /// store (an export, STS-ADMIN-0937) or that the document does not carry
    /// (an import, STS-ADMIN-0938).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<crate::PolicySelection>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTransferProfile {
    /// The policy's kind.
    pub kind: String,
    /// Its name within its kind.
    pub name: String,
    /// True for one of the authentication policy's named policies, which has an
    /// act of its own; false for a kind's profile.
    pub named: bool,
    /// Whether this realm already stores a policy of that kind by that name, so
    /// importing this one would replace it.
    pub replaces: bool,
}

pub type PolicyTransferValue = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTransferView {
    /// The realm this view is about.
    pub realm: String,
    /// `pki.policyExportAlgorithm` in force here: the JWS algorithm the next
    /// export is signed with.
    pub algorithm: String,
    /// Every value that setting may take.
    pub algorithms: Vec<String>,
    /// Whether `pki.paranoidPolicySigner` is on here, which forces the full
    /// paranoid checks on an export's signer in every mode.
    #[serde(rename = "paranoidPolicySigner")]
    pub paranoid_policy_signer: bool,
    /// This realm's Policy Export Signing Issuing CA; null until the first
    /// export builds it.
    #[serde(rename = "issuingCa")]
    pub issuing_ca: Option<crate::PolicyExportIssuingCa>,
    /// The signer truststore's entries in this realm that serve policy-signer:
    /// the chains of the other realms whose exports this realm has trusted.
    #[serde(rename = "trustedSigners")]
    pub trusted_signers: Vec<crate::PolicyTrustedSigner>,
    /// Every policy this realm stores, in Directory → Policies' order: what an
    /// export carries, and what its `policies` may name.
    pub policies: Vec<crate::PolicyExportable>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTrustedSigner {
    pub subject: String,
    pub issuer: String,
    /// `anchor` for a Root, `intermediate` for a CA under one.
    pub kind: String,
    /// The use cases the entry serves; empty serves every one, policy-signer
    /// included.
    pub purposes: Vec<String>,
    /// The SHA-256 fingerprint, upper-case hex with no colons.
    pub fingerprint256: String,
    /// Valid from, ISO 8601; empty where the certificate could not be read.
    #[serde(rename = "notBefore")]
    pub not_before: String,
    /// Valid until, ISO 8601; empty where the certificate could not be read.
    #[serde(rename = "notAfter")]
    pub not_after: String,
    /// `runtime` for an entry an administrator added (an import's yes among
    /// them), `file` for one `pki.signerTrustAnchorsFile` named.
    pub source: String,
    /// Who added it.
    #[serde(rename = "addedBy")]
    pub added_by: String,
    /// When it was added.
    #[serde(rename = "addedAt")]
    pub added_at: String,
    /// Why the entry would no longer be admitted (it expired where it sits, for
    /// one); absent while it would be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unadmittable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanisms: Option<Vec<String>>,
    #[serde(rename = "secondFactors", default, skip_serializing_if = "Option::is_none")]
    pub second_factors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowEnabled {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowActivity {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowSnoozeDays {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowGraceDays {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowNoPasskey {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowMethod {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowAttestation {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PostLoginPolicyRowNoPasskeyFallback {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostLoginPolicyRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enabled: Option<Option<PostLoginPolicyRowEnabled>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub activity: Option<Option<PostLoginPolicyRowActivity>>,
    #[serde(rename = "snoozeDays", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub snooze_days: Option<Option<PostLoginPolicyRowSnoozeDays>>,
    #[serde(rename = "graceDays", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grace_days: Option<Option<PostLoginPolicyRowGraceDays>>,
    #[serde(rename = "noPasskey", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub no_passkey: Option<Option<PostLoginPolicyRowNoPasskey>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub method: Option<Option<PostLoginPolicyRowMethod>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<PostLoginPolicyRowAttestation>>,
    #[serde(rename = "noPasskeyFallback", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub no_passkey_fallback: Option<Option<PostLoginPolicyRowNoPasskeyFallback>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileValueUrls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<sts_model_management_components_2::MembersServerOverrides>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(rename = "changedAt", default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<i64>,
    #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
    pub auto_created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<f64>,
    #[serde(rename = "seenAt", default, skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<ProfileValueUrls>,
}

pub type RfcDocumentResourcePublishedMay = serde_json::Value;

pub type RfcMetadataMemberSValue = serde_json::Value;

/// A refusal or a failure. The sentence is for a person; no error code is ever
/// in it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipValue {
    #[serde(rename = "fedId", default, skip_serializing_if = "Option::is_none")]
    pub fed_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "fedName", default, skip_serializing_if = "Option::is_none")]
    pub fed_name: Option<String>,
    #[serde(rename = "fedRole", default, skip_serializing_if = "Option::is_none")]
    pub fed_role: Option<String>,
    #[serde(rename = "fedProtocol", default, skip_serializing_if = "Option::is_none")]
    pub fed_protocol: Option<String>,
    #[serde(rename = "fedProvider", default, skip_serializing_if = "Option::is_none")]
    pub fed_provider: Option<String>,
    #[serde(rename = "fedPeer", default, skip_serializing_if = "Option::is_none")]
    pub fed_peer: Option<String>,
    #[serde(rename = "fedLocalEntityId", default, skip_serializing_if = "Option::is_none")]
    pub fed_local_entity_id: Option<String>,
    #[serde(rename = "fedEnabled", default, skip_serializing_if = "Option::is_none")]
    pub fed_enabled: Option<String>,
    #[serde(rename = "fedSsoUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_sso_url: Option<String>,
    #[serde(rename = "fedTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_token_url: Option<String>,
    #[serde(rename = "fedUserinfoUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo_url: Option<String>,
    #[serde(rename = "fedJwksUri", default, skip_serializing_if = "Option::is_none")]
    pub fed_jwks_uri: Option<String>,
    #[serde(rename = "fedEmailsUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_emails_url: Option<String>,
    #[serde(rename = "fedJwks", default, skip_serializing_if = "Option::is_none")]
    pub fed_jwks: Option<String>,
    #[serde(rename = "fedTrustAnchor", default, skip_serializing_if = "Option::is_none")]
    pub fed_trust_anchor: Option<String>,
    #[serde(rename = "fedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub fed_signing_certificate: Option<String>,
    #[serde(rename = "fedClientId", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_id: Option<String>,
    #[serde(rename = "fedResponseMode", default, skip_serializing_if = "Option::is_none")]
    pub fed_response_mode: Option<String>,
    #[serde(rename = "fedTeamId", default, skip_serializing_if = "Option::is_none")]
    pub fed_team_id: Option<String>,
    #[serde(rename = "fedKeyId", default, skip_serializing_if = "Option::is_none")]
    pub fed_key_id: Option<String>,
    #[serde(rename = "fedTokenAuth", default, skip_serializing_if = "Option::is_none")]
    pub fed_token_auth: Option<String>,
    #[serde(rename = "fedScope", default, skip_serializing_if = "Option::is_none")]
    pub fed_scope: Option<String>,
    #[serde(rename = "fedResponseType", default, skip_serializing_if = "Option::is_none")]
    pub fed_response_type: Option<String>,
    #[serde(rename = "fedIdTokenSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_id_token_signed_response_alg: Option<String>,
    #[serde(rename = "fedUserinfoSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo_signed_response_alg: Option<String>,
    #[serde(rename = "fedUserinfo", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo: Option<String>,
    #[serde(rename = "fedRefreshTokens", default, skip_serializing_if = "Option::is_none")]
    pub fed_refresh_tokens: Option<String>,
    #[serde(rename = "fedRefreshEverySeconds", default, skip_serializing_if = "Option::is_none")]
    pub fed_refresh_every_seconds: Option<String>,
    #[serde(rename = "fedRegister", default, skip_serializing_if = "Option::is_none")]
    pub fed_register: Option<String>,
    #[serde(rename = "fedRegisteredIssuer", default, skip_serializing_if = "Option::is_none")]
    pub fed_registered_issuer: Option<String>,
    #[serde(rename = "fedRequestObject", default, skip_serializing_if = "Option::is_none")]
    pub fed_request_object: Option<String>,
    #[serde(rename = "fedRequestObjectSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_request_object_signing_alg: Option<String>,
    #[serde(rename = "fedWebFinger", default, skip_serializing_if = "Option::is_none")]
    pub fed_web_finger: Option<String>,
    #[serde(rename = "fedDiscovery", default, skip_serializing_if = "Option::is_none")]
    pub fed_discovery: Option<String>,
    #[serde(rename = "fedFapi", default, skip_serializing_if = "Option::is_none")]
    pub fed_fapi: Option<String>,
    #[serde(rename = "fedInitiateLogin", default, skip_serializing_if = "Option::is_none")]
    pub fed_initiate_login: Option<String>,
    #[serde(rename = "fedBinding", default, skip_serializing_if = "Option::is_none")]
    pub fed_binding: Option<String>,
    #[serde(rename = "fedSignRequest", default, skip_serializing_if = "Option::is_none")]
    pub fed_sign_request: Option<String>,
    #[serde(rename = "fedUsernameSource", default, skip_serializing_if = "Option::is_none")]
    pub fed_username_source: Option<String>,
    #[serde(rename = "fedSubjectClaim", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_claim: Option<String>,
    #[serde(rename = "fedAutocreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub fed_autocreate_users: Option<String>,
    #[serde(rename = "fedUpdateUserAttributes", default, skip_serializing_if = "Option::is_none")]
    pub fed_update_user_attributes: Option<String>,
    #[serde(rename = "fedProvisionGroups", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_groups: Option<String>,
    #[serde(rename = "fedProvisionCap", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_cap: Option<String>,
    #[serde(rename = "fedProvisionIdleMinutes", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_idle_minutes: Option<String>,
    #[serde(rename = "fedSubjectPolicy", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_policy: Option<String>,
    #[serde(rename = "fedSubjectPattern", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_pattern: Option<String>,
    #[serde(rename = "fedMayAssertAdministrators", default, skip_serializing_if = "Option::is_none")]
    pub fed_may_assert_administrators: Option<String>,
    #[serde(rename = "fedSignalEmailMatch", default, skip_serializing_if = "Option::is_none")]
    pub fed_signal_email_match: Option<String>,
    #[serde(rename = "fedSignalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_enabled: Option<String>,
    #[serde(rename = "fedSignalsIssuer", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_issuer: Option<String>,
    #[serde(rename = "fedSignalsDelivery", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_delivery: Option<String>,
    #[serde(rename = "fedSignalsTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_token_url: Option<String>,
    #[serde(rename = "fedSignalsClientId", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_client_id: Option<String>,
    #[serde(rename = "fedSignalsScope", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_scope: Option<String>,
    #[serde(rename = "fedSloUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_slo_url: Option<String>,
    #[serde(rename = "fedSloBinding", default, skip_serializing_if = "Option::is_none")]
    pub fed_slo_binding: Option<String>,
    #[serde(rename = "fedEndSessionUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_end_session_url: Option<String>,
    #[serde(rename = "fedAcceptSignout", default, skip_serializing_if = "Option::is_none")]
    pub fed_accept_signout: Option<String>,
    #[serde(rename = "fedRequireSignedLogout", default, skip_serializing_if = "Option::is_none")]
    pub fed_require_signed_logout: Option<String>,
    #[serde(rename = "fedEncryptionKeyType", default, skip_serializing_if = "Option::is_none")]
    pub fed_encryption_key_type: Option<String>,
    #[serde(rename = "fedKeyManagementAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub fed_key_management_algorithm: Option<String>,
    #[serde(rename = "fedContentEncryptionAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub fed_content_encryption_algorithm: Option<String>,
    #[serde(rename = "fedAllowUnencrypted", default, skip_serializing_if = "Option::is_none")]
    pub fed_allow_unencrypted: Option<String>,
    #[serde(rename = "fedClientCertificate", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_certificate: Option<String>,
    #[serde(rename = "fedAllowUnsolicited", default, skip_serializing_if = "Option::is_none")]
    pub fed_allow_unsolicited: Option<String>,
    #[serde(rename = "fedApplication", default, skip_serializing_if = "Option::is_none")]
    pub fed_application: Option<String>,
    #[serde(rename = "fedAuthnMechanism", default, skip_serializing_if = "Option::is_none")]
    pub fed_authn_mechanism: Option<String>,
    #[serde(rename = "fedAuthnRelationship", default, skip_serializing_if = "Option::is_none")]
    pub fed_authn_relationship: Option<String>,
    #[serde(rename = "fedFirstSeen", default, skip_serializing_if = "Option::is_none")]
    pub fed_first_seen: Option<String>,
    #[serde(rename = "fedLastSeen", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_seen: Option<String>,
    #[serde(rename = "fedAuthentications", default, skip_serializing_if = "Option::is_none")]
    pub fed_authentications: Option<String>,
    #[serde(rename = "fedUsers", default, skip_serializing_if = "Option::is_none")]
    pub fed_users: Option<String>,
    #[serde(rename = "fedLastUser", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_user: Option<String>,
    #[serde(rename = "fedLastError", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_error: Option<String>,
    #[serde(rename = "fedLastErrorAt", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_error_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "fedAllowedTenants", default, skip_serializing_if = "Option::is_none")]
    pub fed_allowed_tenants: Option<Vec<String>>,
    #[serde(rename = "fedAuthorizeParams", default, skip_serializing_if = "Option::is_none")]
    pub fed_authorize_params: Option<Vec<String>>,
    #[serde(rename = "fedAttributeMap", default, skip_serializing_if = "Option::is_none")]
    pub fed_attribute_map: Option<Vec<String>>,
    #[serde(rename = "fedSubjectGroup", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_group: Option<Vec<String>>,
    #[serde(rename = "fedSubjectDomain", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_domain: Option<Vec<String>>,
    #[serde(rename = "fedHomeRealmDomain", default, skip_serializing_if = "Option::is_none")]
    pub fed_home_realm_domain: Option<Vec<String>>,
    #[serde(rename = "fedSignalsEvents", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_events: Option<Vec<String>>,
    #[serde(rename = "fedRelease", default, skip_serializing_if = "Option::is_none")]
    pub fed_release: Option<Vec<String>>,
    #[serde(rename = "fedApplicationUse", default, skip_serializing_if = "Option::is_none")]
    pub fed_application_use: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(rename = "deadLettered", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<crate::SecurityEventTokenSClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub err: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscEventTypesItemMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub required: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscEventTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<RiscEventTypesItemMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountsItemIdentifierChangesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountsItemCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "credentialType", default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(rename = "discoveredAt", default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountsItemEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountsItem {
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub email: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub phone: Option<Option<String>>,
    #[serde(rename = "formerIdentifiers", default, skip_serializing_if = "Option::is_none")]
    pub former_identifiers: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub lifecycle: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "optOut", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub opt_out: Option<Option<String>>,
    #[serde(rename = "optOutApplies", default, skip_serializing_if = "Option::is_none")]
    pub opt_out_applies: Option<bool>,
    #[serde(rename = "credentialStanding", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub credential_standing: Option<Option<String>>,
    #[serde(rename = "credentialChangeRequired", default, skip_serializing_if = "Option::is_none")]
    pub credential_change_required: Option<bool>,
    #[serde(rename = "recoveryActivated", default, skip_serializing_if = "Option::is_none")]
    pub recovery_activated: Option<bool>,
    #[serde(rename = "identifierChanges", default, skip_serializing_if = "Option::is_none")]
    pub identifier_changes: Option<Vec<RiscAccountsItemIdentifierChangesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<RiscAccountsItemCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<RiscAccountsItemEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(rename = "streamCount", default, skip_serializing_if = "Option::is_none")]
    pub stream_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<i64>,
    #[serde(rename = "receiverErrors", default, skip_serializing_if = "Option::is_none")]
    pub receiver_errors: Option<i64>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RiscStreamsItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<RiscStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscCatalogueItemMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub required: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<RiscCatalogueItemMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<RiscSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<RiscSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RiscSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RiscSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RiscSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RiscSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettingsGroupsItemSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<RiscSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<RiscSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<RiscSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<RiscSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<RiscSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<RiscSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<RiscSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<RiscSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub accounts: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub applications: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscPagingAccounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscPagingApplications {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscPagingStreams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscPagingEvents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<RiscPagingAccounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<RiscPagingApplications>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<RiscPagingStreams>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<RiscPagingEvents>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShownAccountsItemIdentifierChangesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShownAccountsItemCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "credentialType", default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(rename = "discoveredAt", default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShownAccountsItemEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShownAccountsItem {
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub email: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub phone: Option<Option<String>>,
    #[serde(rename = "formerIdentifiers", default, skip_serializing_if = "Option::is_none")]
    pub former_identifiers: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub lifecycle: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "optOut", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub opt_out: Option<Option<String>>,
    #[serde(rename = "optOutApplies", default, skip_serializing_if = "Option::is_none")]
    pub opt_out_applies: Option<bool>,
    #[serde(rename = "credentialStanding", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub credential_standing: Option<Option<String>>,
    #[serde(rename = "credentialChangeRequired", default, skip_serializing_if = "Option::is_none")]
    pub credential_change_required: Option<bool>,
    #[serde(rename = "recoveryActivated", default, skip_serializing_if = "Option::is_none")]
    pub recovery_activated: Option<bool>,
    #[serde(rename = "identifierChanges", default, skip_serializing_if = "Option::is_none")]
    pub identifier_changes: Option<Vec<RiscShownAccountsItemIdentifierChangesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<RiscShownAccountsItemCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<RiscShownAccountsItemEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShownApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(rename = "streamCount", default, skip_serializing_if = "Option::is_none")]
    pub stream_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<i64>,
    #[serde(rename = "receiverErrors", default, skip_serializing_if = "Option::is_none")]
    pub receiver_errors: Option<i64>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RiscShownStreamsItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShownStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<RiscShownStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscShown {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<RiscShownAccountsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<RiscShownApplicationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<RiscShownStreamsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscMatched {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscStreamCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taking: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountIdentifierChangesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "credentialType", default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(rename = "discoveredAt", default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccountEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscAccount {
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub email: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub phone: Option<Option<String>>,
    #[serde(rename = "formerIdentifiers", default, skip_serializing_if = "Option::is_none")]
    pub former_identifiers: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub lifecycle: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "optOut", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub opt_out: Option<Option<String>>,
    #[serde(rename = "optOutApplies", default, skip_serializing_if = "Option::is_none")]
    pub opt_out_applies: Option<bool>,
    #[serde(rename = "credentialStanding", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub credential_standing: Option<Option<String>>,
    #[serde(rename = "credentialChangeRequired", default, skip_serializing_if = "Option::is_none")]
    pub credential_change_required: Option<bool>,
    #[serde(rename = "recoveryActivated", default, skip_serializing_if = "Option::is_none")]
    pub recovery_activated: Option<bool>,
    #[serde(rename = "identifierChanges", default, skip_serializing_if = "Option::is_none")]
    pub identifier_changes: Option<Vec<RiscAccountIdentifierChangesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<RiscAccountCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<RiscAccountEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiscEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Risc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "autoEmit", default, skip_serializing_if = "Option::is_none")]
    pub auto_emit: Option<bool>,
    #[serde(rename = "autoEmitActs", default, skip_serializing_if = "Option::is_none")]
    pub auto_emit_acts: Option<Vec<String>>,
    #[serde(rename = "honourOptOut", default, skip_serializing_if = "Option::is_none")]
    pub honour_opt_out: Option<bool>,
    #[serde(rename = "googleSubjectType", default, skip_serializing_if = "Option::is_none")]
    pub google_subject_type: Option<bool>,
    #[serde(rename = "subjectFormat", default, skip_serializing_if = "Option::is_none")]
    pub subject_format: Option<String>,
    #[serde(rename = "omitEventTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub omit_event_timestamp: Option<bool>,
    #[serde(rename = "eventTypes", default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<RiscEventTypesItem>>,
    #[serde(rename = "optStates", default, skip_serializing_if = "Option::is_none")]
    pub opt_states: Option<Vec<String>>,
    #[serde(rename = "lifecycleStates", default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_states: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<RiscAccountsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "ssfEnabled", default, skip_serializing_if = "Option::is_none")]
    pub ssf_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<RiscApplicationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<RiscStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<RiscCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<RiscSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<RiscFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<RiscPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<RiscShown>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<RiscMatched>,
    #[serde(rename = "streamCounts", default, skip_serializing_if = "Option::is_none")]
    pub stream_counts: Option<RiscStreamCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<RiscAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<RiscEventsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootValuePqc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub use_case: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scope: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub alt_key_alg: Option<Option<String>>,
    #[serde(rename = "altSignatureAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub alt_signature_alg: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<bool>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<RootValuePqc>,
}

pub type RowValue = Option<serde_json::Map<String, serde_json::Value>>;

pub type RowsPostgreSqlMariaDbStatisticsView = serde_json::Value;

pub type RulesKindOnlyWhileOnAloneWhileOn = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml11RelyingPartyListProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Saml11RelyingPartyListProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListRelyingPartiesItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slug: Option<Option<String>>,
    #[serde(rename = "idpProviderId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub idp_provider_id: Option<Option<String>>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    #[serde(rename = "responderUrl", default, skip_serializing_if = "Option::is_none")]
    pub responder_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub param: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub noun: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml11RelyingPartyListSettingsGroupsItemSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml11RelyingPartyListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListSettingsGroupsItemSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<Saml11RelyingPartyListSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<Saml11RelyingPartyListSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<Saml11RelyingPartyListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Saml11RelyingPartyListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Saml11RelyingPartyListSettingsContext>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml11RelyingPartyList {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<Saml11RelyingPartyListProtocolEndpointsItem>>,
    #[serde(rename = "relyingParties", default, skip_serializing_if = "Option::is_none")]
    pub relying_parties: Option<Vec<Saml11RelyingPartyListRelyingPartiesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<Saml11RelyingPartyListPaging>,
    #[serde(rename = "unscopedMetadata", default, skip_serializing_if = "Option::is_none")]
    pub unscoped_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Saml11RelyingPartyListSettings>,
    #[serde(rename = "artifactsAwaitingResolution", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_awaiting_resolution: Option<f64>,
    #[serde(rename = "assertionsHeldByReference", default, skip_serializing_if = "Option::is_none")]
    pub assertions_held_by_reference: Option<f64>,
    #[serde(rename = "flowsHeldForSignIn", default, skip_serializing_if = "Option::is_none")]
    pub flows_held_for_sign_in: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(rename = "identifierLooksGuessed", default, skip_serializing_if = "Option::is_none")]
    pub identifier_looks_guessed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slug: Option<Option<String>>,
    #[serde(rename = "idpProviderId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub idp_provider_id: Option<Option<String>>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    #[serde(rename = "responderUrl", default, skip_serializing_if = "Option::is_none")]
    pub responder_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml2ServiceProviderListProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Saml2ServiceProviderListProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListServiceProvidersItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "responseBindings", default, skip_serializing_if = "Option::is_none")]
    pub response_bindings: Option<Vec<String>>,
    #[serde(rename = "lastRequestSigned", default, skip_serializing_if = "Option::is_none")]
    pub last_request_signed: Option<bool>,
    #[serde(rename = "lastRequestVerification", default, skip_serializing_if = "Option::is_none")]
    pub last_request_verification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slug: Option<Option<String>>,
    #[serde(rename = "idpEntityId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub idp_entity_id: Option<Option<String>>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
    #[serde(rename = "arsUrl", default, skip_serializing_if = "Option::is_none")]
    pub ars_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub param: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub noun: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml2ServiceProviderListSettingsGroupsItemSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml2ServiceProviderListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettingsGroupsItemSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<Saml2ServiceProviderListSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<Saml2ServiceProviderListSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<Saml2ServiceProviderListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Saml2ServiceProviderListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Saml2ServiceProviderListSettingsContext>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMdqRefusedItem {
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<String>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMdqRefusedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub param: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub noun: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListLastRequestVerification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(rename = "signatureMethod", default, skip_serializing_if = "Option::is_none")]
    pub signature_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSignedRequestsRequired {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadataRefresh {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "lastSuccessAt", default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadataAssertionConsumerServicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub is_default: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadataSingleLogoutServicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(rename = "responseLocation", default, skip_serializing_if = "Option::is_none")]
    pub response_location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "stateWhy", default, skip_serializing_if = "Option::is_none")]
    pub state_why: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "staleAt", default, skip_serializing_if = "Option::is_none")]
    pub stale_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Saml2ServiceProviderListMetadataRefresh>,
    #[serde(rename = "refresherEnabled", default, skip_serializing_if = "Option::is_none")]
    pub refresher_enabled: Option<bool>,
    #[serde(rename = "refresherRunning", default, skip_serializing_if = "Option::is_none")]
    pub refresher_running: Option<bool>,
    #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
    pub trust_anchors: Option<f64>,
    #[serde(rename = "trustAnchorProblems", default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_problems: Option<Vec<String>>,
    #[serde(rename = "mdqUrl", default, skip_serializing_if = "Option::is_none")]
    pub mdq_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<bool>,
    #[serde(rename = "consumedAt", default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(rename = "signingCertificateConfigured", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate_configured: Option<bool>,
    #[serde(rename = "validUntil", default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "cacheDuration", default, skip_serializing_if = "Option::is_none")]
    pub cache_duration: Option<String>,
    #[serde(rename = "authnRequestsSigned", default, skip_serializing_if = "Option::is_none")]
    pub authn_requests_signed: Option<bool>,
    #[serde(rename = "wantAssertionsSigned", default, skip_serializing_if = "Option::is_none")]
    pub want_assertions_signed: Option<bool>,
    #[serde(rename = "wantAssertionsEncrypted", default, skip_serializing_if = "Option::is_none")]
    pub want_assertions_encrypted: Option<bool>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<Saml2ServiceProviderListMetadataAssertionConsumerServicesItem>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<Saml2ServiceProviderListMetadataSingleLogoutServicesItem>>,
    #[serde(rename = "encryptionCertificate", default, skip_serializing_if = "Option::is_none")]
    pub encryption_certificate: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderList {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<Saml2ServiceProviderListProtocolEndpointsItem>>,
    #[serde(rename = "serviceProviders", default, skip_serializing_if = "Option::is_none")]
    pub service_providers: Option<Vec<Saml2ServiceProviderListServiceProvidersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<Saml2ServiceProviderListPaging>,
    #[serde(rename = "unscopedMetadata", default, skip_serializing_if = "Option::is_none")]
    pub unscoped_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Saml2ServiceProviderListSettings>,
    #[serde(rename = "artifactsAwaitingResolution", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_awaiting_resolution: Option<f64>,
    #[serde(rename = "requestsHeldForSignIn", default, skip_serializing_if = "Option::is_none")]
    pub requests_held_for_sign_in: Option<f64>,
    #[serde(rename = "mdqRefused", default, skip_serializing_if = "Option::is_none")]
    pub mdq_refused: Option<Vec<Saml2ServiceProviderListMdqRefusedItem>>,
    #[serde(rename = "mdqRefusedPaging", default, skip_serializing_if = "Option::is_none")]
    pub mdq_refused_paging: Option<Saml2ServiceProviderListMdqRefusedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "responseBindings", default, skip_serializing_if = "Option::is_none")]
    pub response_bindings: Option<Vec<String>>,
    #[serde(rename = "lastRequestSigned", default, skip_serializing_if = "Option::is_none")]
    pub last_request_signed: Option<bool>,
    #[serde(rename = "lastRequestVerification", default, skip_serializing_if = "Option::is_none")]
    pub last_request_verification: Option<Saml2ServiceProviderListLastRequestVerification>,
    #[serde(rename = "signingCertificate", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate: Option<String>,
    #[serde(rename = "signingCertificates", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificates: Option<Vec<String>>,
    #[serde(rename = "observedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub observed_signing_certificate: Option<String>,
    #[serde(rename = "signedRequestsRequired", default, skip_serializing_if = "Option::is_none")]
    pub signed_requests_required: Option<Saml2ServiceProviderListSignedRequestsRequired>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Saml2ServiceProviderListMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slug: Option<Option<String>>,
    #[serde(rename = "idpEntityId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub idp_entity_id: Option<Option<String>>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
    #[serde(rename = "arsUrl", default, skip_serializing_if = "Option::is_none")]
    pub ars_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAssertionsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SamlAssertionsProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsAssertions {
    #[serde(rename = "saml2LifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub saml2_lifetime_min: Option<f64>,
    #[serde(rename = "saml11LifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub saml11_lifetime_min: Option<f64>,
    #[serde(rename = "clockSkewS", default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_s: Option<f64>,
    #[serde(rename = "saml2WindowS", default, skip_serializing_if = "Option::is_none")]
    pub saml2_window_s: Option<f64>,
    #[serde(rename = "saml11WindowS", default, skip_serializing_if = "Option::is_none")]
    pub saml11_window_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsPerApplicationItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAssertionsSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAssertionsSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<SamlAssertionsSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<SamlAssertionsSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsAssertionsIssuedByKindItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(rename = "noExpiry", default, skip_serializing_if = "Option::is_none")]
    pub no_expiry: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsAssertionsIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<Vec<SamlAssertionsAssertionsIssuedByKindItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertions {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SamlAssertionsProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<SamlAssertionsAssertions>,
    #[serde(rename = "perApplication", default, skip_serializing_if = "Option::is_none")]
    pub per_application: Option<Vec<SamlAssertionsPerApplicationItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<SamlAssertionsSettingsItem>>,
    #[serde(rename = "assertionsIssued", default, skip_serializing_if = "Option::is_none")]
    pub assertions_issued: Option<SamlAssertionsAssertionsIssued>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<SamlAssertionsContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<SamlAssertionsRowsItem>>,
    /// Each setting in seconds, by key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAttributeSetsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SamlAttributeSetsProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsAttributeCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub schema: Option<Option<String>>,
    /// Whether it is ticked, by claim set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub syntax: Option<Option<String>>,
    #[serde(rename = "pacClaimId", default, skip_serializing_if = "Option::is_none")]
    pub pac_claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItemClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItemAttributeReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItemAttributeClaimPreviewItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<bool>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<SamlAttributeSetsSetsItemClaimsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    /// The claims one person would be issued, keyed and nested by the claim
    /// names the catalogue and an administrator chose.
    #[serde(rename = "attributeClaims", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claims: Option<serde_json::Value>,
    #[serde(rename = "attributeReport", default, skip_serializing_if = "Option::is_none")]
    pub attribute_report: Option<Vec<SamlAttributeSetsSetsItemAttributeReportItem>>,
    #[serde(rename = "attributeClaimPreview", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claim_preview: Option<Vec<SamlAttributeSetsSetsItemAttributeClaimPreviewItem>>,
    /// Partners withholding it, by claim.
    #[serde(rename = "withheldFrom", default, skip_serializing_if = "Option::is_none")]
    pub withheld_from: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsAttributeChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// By directory attribute.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsGroupsPreviewGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rule: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Vec<String>>,
    #[serde(rename = "viaMemberOf", default, skip_serializing_if = "Option::is_none")]
    pub via_member_of: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsGroupsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<SamlAttributeSetsGroupsPreviewGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsGroups {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<SamlAttributeSetsGroupsPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsWithholdingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSets {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SamlAttributeSetsProtocolEndpointsItem>>,
    #[serde(rename = "defaultSaml11Namespace", default, skip_serializing_if = "Option::is_none")]
    pub default_saml11_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<Vec<String>>,
    #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub attribute_catalogue: Option<Vec<SamlAttributeSetsAttributeCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<SamlAttributeSetsSetsItem>>,
    #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
    pub attribute_choices: Option<Vec<SamlAttributeSetsAttributeChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<SamlAttributeSetsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<SamlAttributeSetsGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withholding: Option<Vec<SamlAttributeSetsWithholdingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlIdpInitiatedListProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SamlIdpInitiatedListProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListIdpInitiatedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "launchUrl", default, skip_serializing_if = "Option::is_none")]
    pub launch_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListIdpInitiatedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub param: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub noun: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListRealmSwitchesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedList {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SamlIdpInitiatedListProtocolEndpointsItem>>,
    #[serde(rename = "idpInitiated", default, skip_serializing_if = "Option::is_none")]
    pub idp_initiated: Option<Vec<SamlIdpInitiatedListIdpInitiatedItem>>,
    #[serde(rename = "idpInitiatedPaging", default, skip_serializing_if = "Option::is_none")]
    pub idp_initiated_paging: Option<SamlIdpInitiatedListIdpInitiatedPaging>,
    #[serde(rename = "realmSwitches", default, skip_serializing_if = "Option::is_none")]
    pub realm_switches: Option<Vec<SamlIdpInitiatedListRealmSwitchesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ScimProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<ScimProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimStore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "userCount", default, skip_serializing_if = "Option::is_none")]
    pub user_count: Option<f64>,
    #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
    pub group_count: Option<f64>,
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimIdentifiers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimAuthenticationScopes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimAuthenticationSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "refusedByMode", default, skip_serializing_if = "Option::is_none")]
    pub refused_by_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<bool>,
    #[serde(rename = "applicationScoped", default, skip_serializing_if = "Option::is_none")]
    pub application_scoped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(rename = "specUri", default, skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "discoveryOpen", default, skip_serializing_if = "Option::is_none")]
    pub discovery_open: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<ScimAuthenticationScopes>,
    #[serde(rename = "hobaRegistration", default, skip_serializing_if = "Option::is_none")]
    pub hoba_registration: Option<String>,
    #[serde(rename = "digestAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub digest_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<ScimAuthenticationSchemesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimReachableNegativesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMappingUserItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldap: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parent: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<bool>,
    #[serde(rename = "readOnly", default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMappingGroupItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldap: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parent: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<bool>,
    #[serde(rename = "readOnly", default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Vec<ScimMappingUserItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Vec<ScimMappingGroupItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimCountersOperationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimCountersResourceTypesItem {
    #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<ScimCountersOperationsItem>>,
    #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<ScimCountersResourceTypesItem>>,
    /// A count per name.
    #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byScimType", default, skip_serializing_if = "Option::is_none")]
    pub by_scim_type: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byAuthScheme", default, skip_serializing_if = "Option::is_none")]
    pub by_auth_scheme: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ScimSettingsGroupsItemSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ScimSettingsGroupsItemSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettingsGroupsItemSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ScimSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<ScimSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ScimSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ScimSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ScimSettingsContext>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemLastReconcile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovisioned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "notPushedHere", default, skip_serializing_if = "Option::is_none")]
    pub not_pushed_here: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItemCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItemQueuedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItemRetryingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItemDeadItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientsItemByCellItemCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<ScimScimClientsClientsItemByCellItemQueuedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<Vec<ScimScimClientsClientsItemByCellItemRetryingItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<Vec<ScimScimClientsClientsItemByCellItemDeadItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "oauthClientId", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_auth: Option<String>,
    #[serde(rename = "oauthScope", default, skip_serializing_if = "Option::is_none")]
    pub oauth_scope: Option<String>,
    #[serde(rename = "oauthResource", default, skip_serializing_if = "Option::is_none")]
    pub oauth_resource: Option<String>,
    #[serde(rename = "tlsSource", default, skip_serializing_if = "Option::is_none")]
    pub tls_source: Option<String>,
    #[serde(rename = "tlsCertificate", default, skip_serializing_if = "Option::is_none")]
    pub tls_certificate: Option<String>,
    #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
    #[serde(rename = "scopeMode", default, skip_serializing_if = "Option::is_none")]
    pub scope_mode: Option<String>,
    #[serde(rename = "scopeFilter", default, skip_serializing_if = "Option::is_none")]
    pub scope_filter: Option<String>,
    #[serde(rename = "groupMode", default, skip_serializing_if = "Option::is_none")]
    pub group_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovision: Option<String>,
    #[serde(rename = "reconcileMinutes", default, skip_serializing_if = "Option::is_none")]
    pub reconcile_minutes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(rename = "maxRequestsPerSecond", default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_second: Option<String>,
    #[serde(rename = "scopeGroups", default, skip_serializing_if = "Option::is_none")]
    pub scope_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "passwordSet", default, skip_serializing_if = "Option::is_none")]
    pub password_set: Option<bool>,
    #[serde(rename = "oauthClientSecretSet", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_secret_set: Option<bool>,
    #[serde(rename = "tlsPrivateKeySet", default, skip_serializing_if = "Option::is_none")]
    pub tls_private_key_set: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ScimScimClientsClientsItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientsItemCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(rename = "lastReconcile", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile: Option<ScimScimClientsClientsItemLastReconcile>,
    #[serde(rename = "byCell", default, skip_serializing_if = "Option::is_none")]
    pub by_cell: Option<Vec<ScimScimClientsClientsItemByCellItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsChoices {
    #[serde(rename = "authMethods", default, skip_serializing_if = "Option::is_none")]
    pub auth_methods: Option<Vec<String>>,
    #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_auth: Option<Vec<String>>,
    #[serde(rename = "tlsSources", default, skip_serializing_if = "Option::is_none")]
    pub tls_sources: Option<Vec<String>>,
    #[serde(rename = "scopeModes", default, skip_serializing_if = "Option::is_none")]
    pub scope_modes: Option<Vec<String>>,
    #[serde(rename = "groupModes", default, skip_serializing_if = "Option::is_none")]
    pub group_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovision: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientLastReconcile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovisioned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "notPushedHere", default, skip_serializing_if = "Option::is_none")]
    pub not_pushed_here: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItemCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItemQueuedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItemRetryingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItemDeadItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientByCellItemCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<ScimScimClientsClientByCellItemQueuedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<Vec<ScimScimClientsClientByCellItemRetryingItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<Vec<ScimScimClientsClientByCellItemDeadItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesQueuedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesRetryingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesDeadItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueues {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<ScimScimClientsClientQueuesQueuedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<Vec<ScimScimClientsClientQueuesRetryingItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<Vec<ScimScimClientsClientQueuesDeadItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientQueuesCounts>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientDiscovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<bool>,
    /// The path of each resource type, by its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "maxResults", default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bulk: Option<bool>,
    #[serde(rename = "authenticationSchemes", default, skip_serializing_if = "Option::is_none")]
    pub authentication_schemes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "oauthClientId", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_auth: Option<String>,
    #[serde(rename = "oauthScope", default, skip_serializing_if = "Option::is_none")]
    pub oauth_scope: Option<String>,
    #[serde(rename = "oauthResource", default, skip_serializing_if = "Option::is_none")]
    pub oauth_resource: Option<String>,
    #[serde(rename = "tlsSource", default, skip_serializing_if = "Option::is_none")]
    pub tls_source: Option<String>,
    #[serde(rename = "tlsCertificate", default, skip_serializing_if = "Option::is_none")]
    pub tls_certificate: Option<String>,
    #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
    #[serde(rename = "scopeMode", default, skip_serializing_if = "Option::is_none")]
    pub scope_mode: Option<String>,
    #[serde(rename = "scopeFilter", default, skip_serializing_if = "Option::is_none")]
    pub scope_filter: Option<String>,
    #[serde(rename = "groupMode", default, skip_serializing_if = "Option::is_none")]
    pub group_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovision: Option<String>,
    #[serde(rename = "reconcileMinutes", default, skip_serializing_if = "Option::is_none")]
    pub reconcile_minutes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(rename = "maxRequestsPerSecond", default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_second: Option<String>,
    #[serde(rename = "scopeGroups", default, skip_serializing_if = "Option::is_none")]
    pub scope_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "passwordSet", default, skip_serializing_if = "Option::is_none")]
    pub password_set: Option<bool>,
    #[serde(rename = "oauthClientSecretSet", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_secret_set: Option<bool>,
    #[serde(rename = "tlsPrivateKeySet", default, skip_serializing_if = "Option::is_none")]
    pub tls_private_key_set: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ScimScimClientsClientCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(rename = "lastReconcile", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile: Option<ScimScimClientsClientLastReconcile>,
    #[serde(rename = "byCell", default, skip_serializing_if = "Option::is_none")]
    pub by_cell: Option<Vec<ScimScimClientsClientByCellItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queues: Option<ScimScimClientsClientQueues>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<ScimScimClientsClientDiscovery>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClients {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ScimScimClientsClientsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<ScimScimClientsChoices>,
    #[serde(rename = "httpAllowed", default, skip_serializing_if = "Option::is_none")]
    pub http_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ScimScimClientsClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    #[serde(rename = "cellId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cell_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scim {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<ScimProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specifications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<ScimStore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<ScimIdentifiers>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ScimAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<ScimEndpointsItem>>,
    #[serde(rename = "doesNotDo", default, skip_serializing_if = "Option::is_none")]
    pub does_not_do: Option<Vec<String>>,
    #[serde(rename = "reachableNegatives", default, skip_serializing_if = "Option::is_none")]
    pub reachable_negatives: Option<Vec<ScimReachableNegativesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<ScimMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<ScimCounters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ScimSettings>,
    #[serde(rename = "scimClients", default, skip_serializing_if = "Option::is_none")]
    pub scim_clients: Option<ScimScimClients>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "refusedByMode", default, skip_serializing_if = "Option::is_none")]
    pub refused_by_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<bool>,
    #[serde(rename = "applicationScoped", default, skip_serializing_if = "Option::is_none")]
    pub application_scoped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(rename = "specUri", default, skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorStore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "userCount", default, skip_serializing_if = "Option::is_none")]
    pub user_count: Option<f64>,
    #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
    pub group_count: Option<f64>,
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersLatency {
    #[serde(rename = "totalMs", default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    #[serde(rename = "averageMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub average_ms: Option<Option<f64>>,
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    /// A count per name.
    #[serde(rename = "byScheme", default, skip_serializing_if = "Option::is_none")]
    pub by_scheme: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersOperationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(rename = "averageMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub average_ms: Option<Option<f64>>,
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersResourceTypesItem {
    #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersClientsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub principal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<String>>,
    #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<String>>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastOperation", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_operation: Option<Option<String>>,
    #[serde(rename = "lastStatus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_status: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersRecentItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub operation: Option<Option<String>>,
    #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "scimType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scim_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scheme: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub principal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bytes: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub method: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub path: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersRealm {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(rename = "successRate", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub success_rate: Option<Option<f64>>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub since: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<ScimMonitorCountersLatency>,
    #[serde(rename = "bytesOut", default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ScimMonitorCountersAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<ScimMonitorCountersOperationsItem>>,
    #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<ScimMonitorCountersResourceTypesItem>>,
    /// A count per name.
    #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byStatusClass", default, skip_serializing_if = "Option::is_none")]
    pub by_status_class: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byScimType", default, skip_serializing_if = "Option::is_none")]
    pub by_scim_type: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ScimMonitorCountersClientsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent: Option<Vec<ScimMonitorCountersRecentItem>>,
    #[serde(rename = "recentCap", default, skip_serializing_if = "Option::is_none")]
    pub recent_cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<ScimMonitorCountersRealm>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<ScimMonitorSchemesItem>>,
    #[serde(rename = "authRequired", default, skip_serializing_if = "Option::is_none")]
    pub auth_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<ScimMonitorStore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<ScimMonitorCounters>,
}

pub type SecretStoreSOwnApi = serde_json::Value;

pub type SecurityEventTokenSClaims = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowExemptFromSecondFactor {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowBrowserSignIn {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowLdapBind {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowWsTrust {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowScim {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowSsf {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowEst {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowKerberos {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowAllowPasswordGrant {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowRotationEnabled {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowRotationIntervalDays {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowRotationOverlapMinutes {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowGeneratedLength {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowRequireOwner {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ServiceAccountPolicyRowRotationAlarmFailures {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountPolicyRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(rename = "exemptFromSecondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub exempt_from_second_factor: Option<Option<ServiceAccountPolicyRowExemptFromSecondFactor>>,
    #[serde(rename = "allowBrowserSignIn", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_browser_sign_in: Option<Option<ServiceAccountPolicyRowAllowBrowserSignIn>>,
    #[serde(rename = "allowLdapBind", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_ldap_bind: Option<Option<ServiceAccountPolicyRowAllowLdapBind>>,
    #[serde(rename = "allowWsTrust", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_ws_trust: Option<Option<ServiceAccountPolicyRowAllowWsTrust>>,
    #[serde(rename = "allowScim", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_scim: Option<Option<ServiceAccountPolicyRowAllowScim>>,
    #[serde(rename = "allowSsf", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_ssf: Option<Option<ServiceAccountPolicyRowAllowSsf>>,
    #[serde(rename = "allowEst", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_est: Option<Option<ServiceAccountPolicyRowAllowEst>>,
    #[serde(rename = "allowKerberos", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_kerberos: Option<Option<ServiceAccountPolicyRowAllowKerberos>>,
    #[serde(rename = "allowPasswordGrant", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_password_grant: Option<Option<ServiceAccountPolicyRowAllowPasswordGrant>>,
    #[serde(rename = "rotationEnabled", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rotation_enabled: Option<Option<ServiceAccountPolicyRowRotationEnabled>>,
    #[serde(rename = "rotationIntervalDays", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rotation_interval_days: Option<Option<ServiceAccountPolicyRowRotationIntervalDays>>,
    #[serde(rename = "rotationOverlapMinutes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rotation_overlap_minutes: Option<Option<ServiceAccountPolicyRowRotationOverlapMinutes>>,
    #[serde(rename = "generatedLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generated_length: Option<Option<ServiceAccountPolicyRowGeneratedLength>>,
    #[serde(rename = "requireOwner", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub require_owner: Option<Option<ServiceAccountPolicyRowRequireOwner>>,
    #[serde(rename = "rotationAlarmFailures", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rotation_alarm_failures: Option<Option<ServiceAccountPolicyRowRotationAlarmFailures>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountViewOwnersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountViewRotation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "lastAttempt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<ServiceAccountViewOwnersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    #[serde(rename = "previousPasswordExpires", default, skip_serializing_if = "Option::is_none")]
    pub previous_password_expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<ServiceAccountViewRotation>,
    #[serde(rename = "ownerProtected", default, skip_serializing_if = "Option::is_none")]
    pub owner_protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListUnauthenticatedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListAccountChoices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

/// Every session this service is holding right now, filtered and paged.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<f64>,
    #[serde(rename = "heldByKind", default, skip_serializing_if = "Option::is_none")]
    pub held_by_kind: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SessionListFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(rename = "expiryRules", default, skip_serializing_if = "Option::is_none")]
    pub expiry_rules: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<crate::SessionRow>>,
    #[serde(rename = "unauthenticatedHeld", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_held: Option<f64>,
    #[serde(rename = "unauthenticatedKept", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_kept: Option<bool>,
    #[serde(rename = "unauthenticatedSessions", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_sessions: Option<Vec<crate::SessionRow>>,
    #[serde(rename = "unauthenticatedPaging", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_paging: Option<SessionListUnauthenticatedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windowed: Option<bool>,
    #[serde(rename = "accountChoices", default, skip_serializing_if = "Option::is_none")]
    pub account_choices: Option<SessionListAccountChoices>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SessionListPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SessionRowAmr {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRowDeviceBound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<f64>,
    #[serde(rename = "refreshedAt", default, skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

/// One live session of any kind.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
    #[serde(rename = "rpClientId", default, skip_serializing_if = "Option::is_none")]
    pub rp_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "expiryRule", default, skip_serializing_if = "Option::is_none")]
    pub expiry_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<SessionRowAmr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "deviceBound", default, skip_serializing_if = "Option::is_none")]
    pub device_bound: Option<SessionRowDeviceBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "accountSet", default, skip_serializing_if = "Option::is_none")]
    pub account_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// The settings this page draws, described: the same rows GET /config returns,
/// filtered to the ones this page owns.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPageDrawsDescribedSame {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<sts_model_management_components_2::OrderConfig>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    /// How many of them can be changed while the service runs.
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    /// The keys on this page with a runtime override in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    /// The operation that writes them.
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<sts_model_management_components_2::GroupDrawnAnotherPageWell>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig2>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig3>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsValue2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig2>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig3>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsValue3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<crate::WithAdditionalPropertiesPropertiesPage2>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig3>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsValue4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig4>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<crate::WithConfigFileDefaultsFilePersistsAppconfig5>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShownValue {
    /// Base64 keys, by enctype number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming: Option<serde_json::Map<String, serde_json::Value>>,
    /// Base64 keys, by enctype number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SignalsStatusStreamAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsStatusStream {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<SignalsStatusStreamAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(rename = "pollEveryMs", default, skip_serializing_if = "Option::is_none")]
    pub poll_every_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivers: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<i64>,
    #[serde(rename = "caepDelivered", default, skip_serializing_if = "Option::is_none")]
    pub caep_delivered: Option<i64>,
    #[serde(rename = "riscDelivered", default, skip_serializing_if = "Option::is_none")]
    pub risc_delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(rename = "receivePath", default, skip_serializing_if = "Option::is_none")]
    pub receive_path: Option<String>,
    #[serde(rename = "inboxPath", default, skip_serializing_if = "Option::is_none")]
    pub inbox_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sees: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "ssfEnabled", default, skip_serializing_if = "Option::is_none")]
    pub ssf_enabled: Option<bool>,
    #[serde(rename = "internalReceivers", default, skip_serializing_if = "Option::is_none")]
    pub internal_receivers: Option<bool>,
    #[serde(rename = "pushDelivery", default, skip_serializing_if = "Option::is_none")]
    pub push_delivery: Option<bool>,
    #[serde(rename = "caepEnabled", default, skip_serializing_if = "Option::is_none")]
    pub caep_enabled: Option<bool>,
    #[serde(rename = "riscEnabled", default, skip_serializing_if = "Option::is_none")]
    pub risc_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<SignalsStatusStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsReceivedItemReactionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsReceivedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "tokenDigest", default, skip_serializing_if = "Option::is_none")]
    pub token_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub surface: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stream: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(rename = "audienceOk", default, skip_serializing_if = "Option::is_none")]
    pub audience_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// An event's body as this receiver took it in: each event type has its own
    /// members, and a refused delivery is held here too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(rename = "verificationNote", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verification_note: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactions: Option<Vec<SignalsReceivedItemReactionsItem>>,
    #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub content_type: Option<Option<String>>,
    #[serde(rename = "correctMediaType", default, skip_serializing_if = "Option::is_none")]
    pub correct_media_type: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub received: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsPagingReceived {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<SignalsPagingReceived>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SignalsStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<Vec<SignalsReceivedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SignalsFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SignalsPaging>,
}

pub type SoftwareStatementSClaimsRfc = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiffeRegistrationViewSelectorsItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiffeRegistrationView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "spiffeId", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<SpiffeRegistrationViewSelectorsItem>>,
    #[serde(rename = "x509SvidTtl", default, skip_serializing_if = "Option::is_none")]
    pub x509_svid_ttl: Option<f64>,
    #[serde(rename = "jwtSvidTtl", default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_ttl: Option<f64>,
    #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(rename = "federatesWith", default, skip_serializing_if = "Option::is_none")]
    pub federates_with: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downstream: Option<bool>,
    #[serde(rename = "storeSvid", default, skip_serializing_if = "Option::is_none")]
    pub store_svid: Option<bool>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "revisionNumber", default, skip_serializing_if = "Option::is_none")]
    pub revision_number: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "svidsIssued", default, skip_serializing_if = "Option::is_none")]
    pub svids_issued: Option<f64>,
    #[serde(rename = "lastSvidAt", default, skip_serializing_if = "Option::is_none")]
    pub last_svid_at: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "selectorTexts", default, skip_serializing_if = "Option::is_none")]
    pub selector_texts: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfMetadataAuthorizationSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_urn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_subject_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_subject_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_subjects: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_schemes: Option<Vec<SsfMetadataAuthorizationSchemesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_subject_members: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeliveryItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfPushTransport {
    #[serde(rename = "allowHttp", default, skip_serializing_if = "Option::is_none")]
    pub allow_http: Option<bool>,
    #[serde(rename = "skipTlsVerificationSet", default, skip_serializing_if = "Option::is_none")]
    pub skip_tls_verification_set: Option<bool>,
    #[serde(rename = "skipTlsVerification", default, skip_serializing_if = "Option::is_none")]
    pub skip_tls_verification: Option<bool>,
    #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfPush {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<SsfPushTransport>,
    #[serde(rename = "allowedHosts", default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<f64>,
    #[serde(rename = "maxResponseBytes", default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfEventTypesItemMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub required: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfEventTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<SsfEventTypesItemMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSubjectFormatsItemExampleIdentifiersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSubjectFormatsItemExample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_id: Option<String>,
    #[serde(rename = "ip-addresses", default, skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<Vec<SsfSubjectFormatsItemExampleIdentifiersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSubjectFormatsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<SsfSubjectFormatsItemExample>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfComplexSubjectMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfAuthenticationScopes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
    #[serde(rename = "readAlso", default, skip_serializing_if = "Option::is_none")]
    pub read_also: Option<Vec<String>>,
    #[serde(rename = "writeAlso", default, skip_serializing_if = "Option::is_none")]
    pub write_also: Option<Vec<String>>,
    #[serde(rename = "writeIncludesRead", default, skip_serializing_if = "Option::is_none")]
    pub write_includes_read: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfAuthenticationSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_urn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<SsfAuthenticationScopes>,
    #[serde(rename = "refusedPassword", default, skip_serializing_if = "Option::is_none")]
    pub refused_password: Option<String>,
    #[serde(rename = "metadataIsOpen", default, skip_serializing_if = "Option::is_none")]
    pub metadata_is_open: Option<bool>,
    #[serde(rename = "passwordVerified", default, skip_serializing_if = "Option::is_none")]
    pub password_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<SsfAuthenticationSchemesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfReachableNegativesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfStreamDetailItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemDelivery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint_url: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemSubjectsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verified: Option<Option<bool>>,
    #[serde(rename = "addedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub added_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    /// An RFC 9493 subject identifier, as a stream was given it or a person
    /// named it: the format decides the members, an `aliases` nests, and SSF
    /// 1.0 section 3.3 lets a receiver add its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfStreamDetailItemQueueItemSummaryAudience {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemQueueItemSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<SsfStreamDetailItemQueueItemSummaryAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemQueueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deliveredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub delivered_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<SsfStreamDetailItemQueueItemSummary>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfStreamDetailItemDeadLettersItemSummaryAudience {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemDeadLettersItemSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<SsfStreamDetailItemDeadLettersItemSummaryAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemDeadLettersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deadAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dead_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<SsfStreamDetailItemDeadLettersItemSummary>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemLogItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<SsfStreamDetailItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<SsfStreamDetailItemDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub format: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<SsfStreamDetailItemSubjectsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<Vec<SsfStreamDetailItemQueueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<bool>,
    #[serde(rename = "deadSince", default, skip_serializing_if = "Option::is_none")]
    pub dead_since: Option<String>,
    #[serde(rename = "deadReason", default, skip_serializing_if = "Option::is_none")]
    pub dead_reason: Option<String>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(rename = "nextProbeAt", default, skip_serializing_if = "Option::is_none")]
    pub next_probe_at: Option<String>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<Vec<SsfStreamDetailItemDeadLettersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<SsfStreamDetailItemLogItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLetters_2Pushes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLetters_2 {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<f64>,
    #[serde(rename = "maxPerStream", default, skip_serializing_if = "Option::is_none")]
    pub max_per_stream: Option<f64>,
    #[serde(rename = "deadStreamTimeoutS", default, skip_serializing_if = "Option::is_none")]
    pub dead_stream_timeout_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<SsfDeadLetters_2Pushes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<SsfSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<SsfSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItemSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<SsfSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<SsfSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<SsfSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<SsfSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<SsfSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<SsfSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<SsfSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<SsfSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamTotals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<i64>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfPagingStreams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<SsfPagingStreams>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SsfProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssf {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SsfMetadata>,
    #[serde(rename = "signingAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub signing_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Vec<SsfDeliveryItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<SsfPush>,
    #[serde(rename = "eventTypes", default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<SsfEventTypesItem>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<SsfSubjectFormatsItem>>,
    #[serde(rename = "complexSubjectMembers", default, skip_serializing_if = "Option::is_none")]
    pub complex_subject_members: Option<Vec<SsfComplexSubjectMembersItem>>,
    #[serde(rename = "criticalSubjectMembers", default, skip_serializing_if = "Option::is_none")]
    pub critical_subject_members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SsfAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<SsfStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<SsfEndpointsItem>>,
    #[serde(rename = "reachableNegatives", default, skip_serializing_if = "Option::is_none")]
    pub reachable_negatives: Option<Vec<SsfReachableNegativesItem>>,
    #[serde(rename = "doesNotDo", default, skip_serializing_if = "Option::is_none")]
    pub does_not_do: Option<Vec<String>>,
    #[serde(rename = "streamDetail", default, skip_serializing_if = "Option::is_none")]
    pub stream_detail: Option<Vec<SsfStreamDetailItem>>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<SsfDeadLetters_2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SsfSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statuses: Option<Vec<String>>,
    #[serde(rename = "streamTotals", default, skip_serializing_if = "Option::is_none")]
    pub stream_totals: Option<SsfStreamTotals>,
    #[serde(rename = "streamFilter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stream_filter: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SsfPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SsfProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersCausesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersTotals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(rename = "streamsHolding", default, skip_serializing_if = "Option::is_none")]
    pub streams_holding: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<i64>,
    #[serde(rename = "deadStreams", default, skip_serializing_if = "Option::is_none")]
    pub dead_streams: Option<i64>,
    #[serde(rename = "halfOpenStreams", default, skip_serializing_if = "Option::is_none")]
    pub half_open_streams: Option<i64>,
    #[serde(rename = "failingStreams", default, skip_serializing_if = "Option::is_none")]
    pub failing_streams: Option<i64>,
    #[serde(rename = "pushStreams", default, skip_serializing_if = "Option::is_none")]
    pub push_streams: Option<i64>,
    #[serde(rename = "oldestAt", default, skip_serializing_if = "Option::is_none")]
    pub oldest_at: Option<String>,
    #[serde(rename = "newestAt", default, skip_serializing_if = "Option::is_none")]
    pub newest_at: Option<String>,
    #[serde(rename = "oldestAgeS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub oldest_age_s: Option<Option<f64>>,
    #[serde(rename = "newestAgeS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub newest_age_s: Option<Option<f64>>,
    #[serde(rename = "deadLetteredEver", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettered_ever: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersTimelineBucketsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(rename = "startMs", default, skip_serializing_if = "Option::is_none")]
    pub start_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersTimeline {
    #[serde(rename = "bucketS", default, skip_serializing_if = "Option::is_none")]
    pub bucket_s: Option<f64>,
    #[serde(rename = "windowS", default, skip_serializing_if = "Option::is_none")]
    pub window_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets: Option<Vec<SsfDeadLettersTimelineBucketsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak: Option<i64>,
    #[serde(rename = "olderThanWindow", default, skip_serializing_if = "Option::is_none")]
    pub older_than_window: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersByCodeItem {
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersByStatusItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersByEventTypeItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfDeadLettersStreamsItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<SsfDeadLettersStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "oldestAt", default, skip_serializing_if = "Option::is_none")]
    pub oldest_at: Option<String>,
    #[serde(rename = "newestAt", default, skip_serializing_if = "Option::is_none")]
    pub newest_at: Option<String>,
    #[serde(rename = "deadLetteredEver", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettered_ever: Option<f64>,
    #[serde(rename = "deadSince", default, skip_serializing_if = "Option::is_none")]
    pub dead_since: Option<String>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(rename = "nextProbeAt", default, skip_serializing_if = "Option::is_none")]
    pub next_probe_at: Option<String>,
    #[serde(rename = "deadReason", default, skip_serializing_if = "Option::is_none")]
    pub dead_reason: Option<String>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none")]
    pub last_push_error: Option<String>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersLettersItemEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersLettersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deadAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dead_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "ageS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub age_s: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(rename = "streamKnown", default, skip_serializing_if = "Option::is_none")]
    pub stream_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<SsfDeadLettersLettersItemEvent>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersSettings {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<f64>,
    #[serde(rename = "maxPerStream", default, skip_serializing_if = "Option::is_none")]
    pub max_per_stream: Option<f64>,
    #[serde(rename = "deadStreamTimeoutS", default, skip_serializing_if = "Option::is_none")]
    pub dead_stream_timeout_s: Option<f64>,
    #[serde(rename = "sweepS", default, skip_serializing_if = "Option::is_none")]
    pub sweep_s: Option<f64>,
    #[serde(rename = "pushConcurrency", default, skip_serializing_if = "Option::is_none")]
    pub push_concurrency: Option<f64>,
    #[serde(rename = "pushBacklog", default, skip_serializing_if = "Option::is_none")]
    pub push_backlog: Option<f64>,
    #[serde(rename = "pushRetries", default, skip_serializing_if = "Option::is_none")]
    pub push_retries: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcessPushes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcessSweepsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphaned: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<i64>,
    #[serde(rename = "deadStreams", default, skip_serializing_if = "Option::is_none")]
    pub dead_streams: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcessSinceStart {
    #[serde(rename = "firstSweepAt", default, skip_serializing_if = "Option::is_none")]
    pub first_sweep_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweeps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphaned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcess {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thread: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<SsfDeadLettersProcessPushes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweeps: Option<Vec<SsfDeadLettersProcessSweepsItem>>,
    #[serde(rename = "sinceStart", default, skip_serializing_if = "Option::is_none")]
    pub since_start: Option<SsfDeadLettersProcessSinceStart>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stream: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cause: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersPagingLetters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersPagingStreams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<SsfDeadLettersPagingLetters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<SsfDeadLettersPagingStreams>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLetters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(rename = "pushDelivery", default, skip_serializing_if = "Option::is_none")]
    pub push_delivery: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causes: Option<Vec<SsfDeadLettersCausesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<SsfDeadLettersTotals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SsfDeadLettersTimeline>,
    #[serde(rename = "byCode", default, skip_serializing_if = "Option::is_none")]
    pub by_code: Option<Vec<SsfDeadLettersByCodeItem>>,
    #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<Vec<SsfDeadLettersByStatusItem>>,
    #[serde(rename = "byEventType", default, skip_serializing_if = "Option::is_none")]
    pub by_event_type: Option<Vec<SsfDeadLettersByEventTypeItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<SsfDeadLettersStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<Vec<SsfDeadLettersLettersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SsfDeadLettersSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<SsfDeadLettersProcess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SsfDeadLettersFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SsfDeadLettersPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsValue {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub read: Option<Option<String>>,
    #[serde(rename = "memoryUsageBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub memory_usage_bytes: Option<Option<f64>>,
    #[serde(rename = "memoryLimitBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub memory_limit_bytes: Option<Option<f64>>,
    #[serde(rename = "memoryLimitUnlimited", default, skip_serializing_if = "Option::is_none")]
    pub memory_limit_unlimited: Option<bool>,
    #[serde(rename = "cpuCoresUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cpu_cores_used: Option<Option<f64>>,
    #[serde(rename = "cpuPercentOfTaskLimit", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cpu_percent_of_task_limit: Option<Option<f64>>,
}

/// What this service is and how much it has done since it started.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(rename = "uptimeMs", default, skip_serializing_if = "Option::is_none")]
    pub uptime_ms: Option<f64>,
    /// Endpoint calls served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<i64>,
    #[serde(rename = "tokensHeld", default, skip_serializing_if = "Option::is_none")]
    pub tokens_held: Option<i64>,
    /// True when the token register is read on demand (#820): tokensHeld counts
    /// the recent tokens this process holds, not every token issued.
    #[serde(rename = "tokensHeldOnly", default, skip_serializing_if = "Option::is_none")]
    pub tokens_held_only: Option<bool>,
    #[serde(rename = "tokensRevoked", default, skip_serializing_if = "Option::is_none")]
    pub tokens_revoked: Option<i64>,
    /// Assertions, tickets and credentials: everything that is not a JWT.
    #[serde(rename = "artifactsHeld", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_held: Option<i64>,
    /// Browser sign-on sessions really held.
    #[serde(rename = "signOnSessions", default, skip_serializing_if = "Option::is_none")]
    pub sign_on_sessions: Option<i64>,
    #[serde(rename = "usersKnown", default, skip_serializing_if = "Option::is_none")]
    pub users_known: Option<i64>,
    #[serde(rename = "usersAuthenticatedHere", default, skip_serializing_if = "Option::is_none")]
    pub users_authenticated_here: Option<i64>,
    /// The console pages this API mirrors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_supported: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<crate::WithMethodEndpointurlAdditionalProperties>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLimitsValue {
    #[serde(rename = "cpuVcpus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cpu_vcpus: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    #[serde(rename = "memoryMiB", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub memory_mi_b: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottlingValue {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub periods: Option<Option<f64>>,
    #[serde(rename = "throttledPeriods", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub throttled_periods: Option<Option<f64>>,
    #[serde(rename = "throttledSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub throttled_seconds: Option<Option<f64>>,
    #[serde(rename = "throttledPercentOfPeriods", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub throttled_percent_of_periods: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesLifetimes {
    #[serde(rename = "accessTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub access_token_ttl_s: Option<f64>,
    #[serde(rename = "idTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub id_token_ttl_s: Option<f64>,
    #[serde(rename = "refreshTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_ttl_s: Option<f64>,
    #[serde(rename = "clockSkewS", default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesSettingsItemSelectAllOnlyWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<TokenLifetimesSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<TokenLifetimesSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TokenLifetimesSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TokenLifetimesSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each of a list's values.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<TokenLifetimesSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<TokenLifetimesSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<TokenLifetimesSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesTokensByKindItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "notYetValid", default, skip_serializing_if = "Option::is_none")]
    pub not_yet_valid: Option<i64>,
    #[serde(rename = "noExpiry", default, skip_serializing_if = "Option::is_none")]
    pub no_expiry: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<Vec<TokenLifetimesTokensByKindItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesOverridableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetimes: Option<TokenLifetimesLifetimes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<TokenLifetimesSettingsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenLifetimesTokens>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<TokenLifetimesContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridable: Option<Vec<TokenLifetimesOverridableItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustValueOutgoing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "setAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub set_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustValueEnctypeNamesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustValue {
    #[serde(rename = "partnerRealm", default, skip_serializing_if = "Option::is_none")]
    pub partner_realm: Option<String>,
    #[serde(rename = "netbiosName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub netbios_name: Option<Option<String>>,
    #[serde(rename = "partnerSid", default, skip_serializing_if = "Option::is_none")]
    pub partner_sid: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "partnerTrustRealm", default, skip_serializing_if = "Option::is_none")]
    pub partner_trust_realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(rename = "trustDirection", default, skip_serializing_if = "Option::is_none")]
    pub trust_direction: Option<i64>,
    #[serde(rename = "trustAttributes", default, skip_serializing_if = "Option::is_none")]
    pub trust_attributes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enctypes: Option<Vec<i64>>,
    #[serde(rename = "forestTrustInfo", default, skip_serializing_if = "Option::is_none")]
    pub forest_trust_info: Option<sts_model_management_components_2::ForestTrustInfoValue>,
    #[serde(rename = "claimsTransformation", default, skip_serializing_if = "Option::is_none")]
    pub claims_transformation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming: Option<crate::WithPreviousHeldKvno>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing: Option<TrustValueOutgoing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<String>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<String>>,
    #[serde(rename = "enctypeNames", default, skip_serializing_if = "Option::is_none")]
    pub enctype_names: Option<Vec<TrustValueEnctypeNamesItem>>,
    #[serde(rename = "lastKeyChangeAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_key_change_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<crate::WithAdditionalPropertiesPropertiesPartnerRealm>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserFormsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserRealmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserProtocolsItemMethodsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<UserDetailUserProtocolsItemMethodsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailUserEventsItemAmr {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<UserDetailUserEventsItemAmr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserArtifactKindsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forms: Option<Vec<UserDetailUserFormsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<UserDetailUserRealmsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<UserDetailUserProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
    pub is_client: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "knownBy", default, skip_serializing_if = "Option::is_none")]
    pub known_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<UserDetailUserEventsItem>>,
    #[serde(rename = "eventsForgotten", default, skip_serializing_if = "Option::is_none")]
    pub events_forgotten: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<UserDetailUserTokens>,
    #[serde(rename = "artifactKinds", default, skip_serializing_if = "Option::is_none")]
    pub artifact_kinds: Option<Vec<UserDetailUserArtifactKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<f64>,
    #[serde(rename = "lastActivityAt", default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountOwnersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountRotation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotates: Option<bool>,
    #[serde(rename = "nextDueAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_due_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_attempt_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarm: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountPolicy {
    #[serde(rename = "exemptFromSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub exempt_from_second_factor: Option<bool>,
    #[serde(rename = "allowBrowserSignIn", default, skip_serializing_if = "Option::is_none")]
    pub allow_browser_sign_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<Vec<String>>,
    #[serde(rename = "requiresOwner", default, skip_serializing_if = "Option::is_none")]
    pub requires_owner: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<UserDetailServiceAccountOwnersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<UserDetailServiceAccountOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub destination: Option<Option<String>>,
    #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub secret_name: Option<Option<String>>,
    #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rotated_at: Option<Option<String>>,
    #[serde(rename = "previousPasswordUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous_password_until: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<UserDetailServiceAccountRotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<UserDetailServiceAccountPolicy>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailRisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "lastAssessment", default, skip_serializing_if = "Option::is_none")]
    pub last_assessment: Option<String>,
    #[serde(rename = "crossedAt", default, skip_serializing_if = "Option::is_none")]
    pub crossed_at: Option<f64>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsPasswordResetLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsMfaRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "byUser", default, skip_serializing_if = "Option::is_none")]
    pub by_user: Option<bool>,
    #[serde(rename = "byRealm", default, skip_serializing_if = "Option::is_none")]
    pub by_realm: Option<bool>,
    #[serde(rename = "byAdministrator", default, skip_serializing_if = "Option::is_none")]
    pub by_administrator: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(rename = "exemptServiceAccount", default, skip_serializing_if = "Option::is_none")]
    pub exempt_service_account: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsTotpDetail {
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unusable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAlgorithm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemAnchor>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithmsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailFactorsKeysItemAttestationAlgorithmsAnchor>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithmsMembersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "objectDigest", default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<String>,
    #[serde(rename = "evidenceRecord", default, skip_serializing_if = "Option::is_none")]
    pub evidence_record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renewed_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renew_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "hashAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub tsa: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAndroidRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub checked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "certificationLevel", default, skip_serializing_if = "Option::is_none")]
    pub certification_level: Option<String>,
    #[serde(rename = "mdsStatus", default, skip_serializing_if = "Option::is_none")]
    pub mds_status: Option<String>,
    #[serde(rename = "mdsVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mds_version: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<UserDetailFactorsKeysItemAttestationAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conveyance: Option<String>,
    #[serde(rename = "enterpriseDowngraded", default, skip_serializing_if = "Option::is_none")]
    pub enterprise_downgraded: Option<bool>,
    #[serde(rename = "attestationKeyId", default, skip_serializing_if = "Option::is_none")]
    pub attestation_key_id: Option<String>,
    #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none")]
    pub device_serial: Option<String>,
    #[serde(rename = "deviceSerialSource", default, skip_serializing_if = "Option::is_none")]
    pub device_serial_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<UserDetailFactorsKeysItemAttestationEvidence>,
    #[serde(rename = "androidRevocation", default, skip_serializing_if = "Option::is_none")]
    pub android_revocation: Option<UserDetailFactorsKeysItemAttestationAndroidRevocation>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithms_2CertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithms_2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statements: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithms_2CertificatesItem>>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemPossiblyReplaced {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemWithoutUsername {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItem {
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(rename = "signCount", default, skip_serializing_if = "Option::is_none")]
    pub sign_count: Option<f64>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<UserDetailFactorsKeysItemAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailFactorsKeysItemAttestation>,
    #[serde(rename = "attestationAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub attestation_algorithms: Option<UserDetailFactorsKeysItemAttestationAlgorithms_2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub provider: Option<Option<String>>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(rename = "backupEligible", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_eligible: Option<Option<bool>>,
    #[serde(rename = "backupState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_state: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub discoverable: Option<Option<bool>>,
    #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub device_serial: Option<Option<String>>,
    #[serde(rename = "possiblyReplaced", default, skip_serializing_if = "Option::is_none")]
    pub possibly_replaced: Option<UserDetailFactorsKeysItemPossiblyReplaced>,
    #[serde(rename = "withoutUsername", default, skip_serializing_if = "Option::is_none")]
    pub without_username: Option<UserDetailFactorsKeysItemWithoutUsername>,
    #[serde(rename = "postQuantumRefused", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_refused: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsAppPasswordsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<Vec<String>>,
    #[serde(rename = "doorLabels", default, skip_serializing_if = "Option::is_none")]
    pub door_labels: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(rename = "lastUsedDoor", default, skip_serializing_if = "Option::is_none")]
    pub last_used_door: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsPasswordOnlyDoors {
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Vec<String>>,
    #[serde(rename = "passwordAloneDoors", default, skip_serializing_if = "Option::is_none")]
    pub password_alone_doors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsPolicy {
    #[serde(rename = "totpEnabled", default, skip_serializing_if = "Option::is_none")]
    pub totp_enabled: Option<bool>,
    #[serde(rename = "backupCodesEnabled", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes_enabled: Option<bool>,
    #[serde(rename = "backupCodesCount", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes_count: Option<f64>,
    #[serde(rename = "webauthnEnabled", default, skip_serializing_if = "Option::is_none")]
    pub webauthn_enabled: Option<bool>,
    #[serde(rename = "primaryAllowed", default, skip_serializing_if = "Option::is_none")]
    pub primary_allowed: Option<bool>,
    #[serde(rename = "mfaAllowed", default, skip_serializing_if = "Option::is_none")]
    pub mfa_allowed: Option<bool>,
    #[serde(rename = "maxKeysPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_keys_per_person: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    #[serde(rename = "passwordChangeRequired", default, skip_serializing_if = "Option::is_none")]
    pub password_change_required: Option<bool>,
    #[serde(rename = "passwordResetLink", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_link: Option<UserDetailFactorsPasswordResetLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(rename = "mfaRequirement", default, skip_serializing_if = "Option::is_none")]
    pub mfa_requirement: Option<UserDetailFactorsMfaRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<bool>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub second_factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
    pub totp_usable: Option<bool>,
    #[serde(rename = "totpDetail", default, skip_serializing_if = "Option::is_none")]
    pub totp_detail: Option<UserDetailFactorsTotpDetail>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<UserDetailFactorsBackupCodes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailFactorsKeysItem>>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "mfaKeys", default, skip_serializing_if = "Option::is_none")]
    pub mfa_keys: Option<f64>,
    #[serde(rename = "appPasswords", default, skip_serializing_if = "Option::is_none")]
    pub app_passwords: Option<Vec<UserDetailFactorsAppPasswordsItem>>,
    #[serde(rename = "passwordOnlyDoors", default, skip_serializing_if = "Option::is_none")]
    pub password_only_doors: Option<UserDetailFactorsPasswordOnlyDoors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<UserDetailFactorsPolicy>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItemDeviceBound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<f64>,
    #[serde(rename = "refreshedAt", default, skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailSessionsItemTokensItemClientId {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailSessionsItemTokensItemScope {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItemTokensItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<UserDetailSessionsItemTokensItemClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserDetailSessionsItemTokensItemScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5tSpki", default, skip_serializing_if = "Option::is_none")]
    pub x5t_spki: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(rename = "grantRefresh", default, skip_serializing_if = "Option::is_none")]
    pub grant_refresh: Option<bool>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItemTokensPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(rename = "authTime", default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "wsfedRealms", default, skip_serializing_if = "Option::is_none")]
    pub wsfed_realms: Option<Vec<String>>,
    #[serde(rename = "deviceBound", default, skip_serializing_if = "Option::is_none")]
    pub device_bound: Option<UserDetailSessionsItemDeviceBound>,
    #[serde(rename = "accountSet", default, skip_serializing_if = "Option::is_none")]
    pub account_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<UserDetailSessionsItemTokensItem>>,
    #[serde(rename = "tokensPaging", default, skip_serializing_if = "Option::is_none")]
    pub tokens_paging: Option<UserDetailSessionsItemTokensPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailTokensOnEndedSessionsItemClientId {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailTokensOnEndedSessionsItemScope {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensOnEndedSessionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<UserDetailTokensOnEndedSessionsItemClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserDetailTokensOnEndedSessionsItemScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5tSpki", default, skip_serializing_if = "Option::is_none")]
    pub x5t_spki: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(rename = "grantRefresh", default, skip_serializing_if = "Option::is_none")]
    pub grant_refresh: Option<bool>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensOnEndedSessionsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailTokensWithNoSessionItemClientId {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailTokensWithNoSessionItemScope {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensWithNoSessionItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<UserDetailTokensWithNoSessionItemClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserDetailTokensWithNoSessionItemScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5tSpki", default, skip_serializing_if = "Option::is_none")]
    pub x5t_spki: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(rename = "grantRefresh", default, skip_serializing_if = "Option::is_none")]
    pub grant_refresh: Option<bool>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensWithNoSessionPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailArtifactsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "claimSet", default, skip_serializing_if = "Option::is_none")]
    pub claim_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "pacClaims", default, skip_serializing_if = "Option::is_none")]
    pub pac_claims: Option<f64>,
    #[serde(rename = "entryId", default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    #[serde(rename = "configId", default, skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailArtifactsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailLdapEntryMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "userKey", default, skip_serializing_if = "Option::is_none")]
    pub user_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailLdapEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<UserDetailLdapEntryMembersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailLdap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<UserDetailLdapEntry>,
    #[serde(rename = "alsoNamed", default, skip_serializing_if = "Option::is_none")]
    pub also_named: Option<Vec<String>>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "usersDn", default, skip_serializing_if = "Option::is_none")]
    pub users_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
    #[serde(rename = "listenError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub listen_error: Option<Option<String>>,
    #[serde(rename = "ldapsPort", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldaps_port: Option<Option<f64>>,
    #[serde(rename = "ldapsListening", default, skip_serializing_if = "Option::is_none")]
    pub ldaps_listening: Option<bool>,
    #[serde(rename = "autoCreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub auto_create_users: Option<bool>,
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemKeysItemCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemKeysItemChainItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<UserDetailCredentialsKeyPairsItemKeysItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<UserDetailCredentialsKeyPairsItemKeysItemChainItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailCredentialsKeyPairsItemKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
    pub at_cap: Option<bool>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(rename = "effectiveIssuers", default, skip_serializing_if = "Option::is_none")]
    pub effective_issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserDetailCredentialsKeyPairsItemAttributes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(rename = "keyPairs", default, skip_serializing_if = "Option::is_none")]
    pub key_pairs: Option<Vec<UserDetailCredentialsKeyPairsItem>>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reasons: Option<Vec<String>>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(rename = "sealsAtRest", default, skip_serializing_if = "Option::is_none")]
    pub seals_at_rest: Option<bool>,
    #[serde(rename = "selfService", default, skip_serializing_if = "Option::is_none")]
    pub self_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFederationLinksItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "relationshipExists", default, skip_serializing_if = "Option::is_none")]
    pub relationship_exists: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFederationLinksPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeysEtypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeysRetainedItemEtypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeysRetainedItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kvno: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<UserDetailKerberosKeysRetainedItemEtypesItem>>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeys {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kvno: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<UserDetailKerberosKeysEtypesItem>>,
    #[serde(rename = "derivedAt", default, skip_serializing_if = "Option::is_none")]
    pub derived_at: Option<String>,
    #[serde(rename = "derivedOn", default, skip_serializing_if = "Option::is_none")]
    pub derived_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained: Option<Vec<UserDetailKerberosKeysRetainedItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberos {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdc: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none")]
    pub trust_realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "productKdc", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub product_kdc: Option<Option<bool>>,
    #[serde(rename = "personKeys", default, skip_serializing_if = "Option::is_none")]
    pub person_keys: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(rename = "nameUsable", default, skip_serializing_if = "Option::is_none")]
    pub name_usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<UserDetailKerberosKeys>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAttributeEditorAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAttributeEditorWithheldItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAttributeEditor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<UserDetailAttributeEditorAttributesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<Vec<UserDetailAttributeEditorWithheldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonyms: Option<Vec<String>>,
    #[serde(rename = "pseudonymPending", default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_pending: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsItemFinalization {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsItemTokensItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issued_at: Option<Option<f64>>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<bool>,
    /// An RFC 9635 access right as the client asked for it: a reference string
    /// or an object in the access type the resource server defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<serde_json::Value>,
    #[serde(rename = "revokedWhy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_why: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization: Option<UserDetailGnapGrantsItemFinalization>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client: Option<Option<String>>,
    #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_name: Option<Option<String>>,
    #[serde(rename = "authorizationServer", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub authorization_server: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<f64>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<f64>>,
    #[serde(rename = "grantExpiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grant_expires_at: Option<Option<f64>>,
    #[serde(rename = "approvedBy", default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// An RFC 9635 access right as the client asked for it: a reference string
    /// or an object in the access type the resource server defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rights: Option<serde_json::Value>,
    #[serde(rename = "rightsAre", default, skip_serializing_if = "Option::is_none")]
    pub rights_are: Option<String>,
    #[serde(rename = "subjectReleasedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject_released_at: Option<Option<f64>>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub derived_from: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<UserDetailGnapGrantsItemTokensItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsCells {
    #[serde(rename = "multiCell", default, skip_serializing_if = "Option::is_none")]
    pub multi_cell: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaResourcesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaSharesItemRecipient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaSharesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<UserDetailUmaSharesItemRecipient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
    pub ask_me: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailUmaHeldItemPermissions {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaHeldItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "requestingParty", default, skip_serializing_if = "Option::is_none")]
    pub requesting_party: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<UserDetailUmaHeldItemPermissions>,
    #[serde(rename = "upgradedFrom", default, skip_serializing_if = "Option::is_none")]
    pub upgraded_from: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailUmaPendingItemPermissions {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaPendingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<UserDetailUmaPendingItemPermissions>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUma {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<UserDetailUmaResourcesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<UserDetailUmaSharesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<UserDetailUmaHeldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Vec<UserDetailUmaPendingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAuthenticationEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(rename = "actorForm", default, skip_serializing_if = "Option::is_none")]
    pub actor_form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// What the call site that wrote the audit row chose to record, which
    /// differs at each of hundreds of them; the keys and the values are data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAuthenticationEventsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAuthenticationEventsLog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<f64>,
    #[serde(rename = "maxEvents", default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessionless: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemPublicKeyJwk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(rename = "pub", default, skip_serializing_if = "Option::is_none")]
    pub pub_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAlgorithmV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailPageMfaMechKeysItemAlgorithm {
    V1(UserDetailPageMfaMechKeysItemAlgorithmV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemAnchor>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaMechKeysItemAttestationAlgorithmsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailPageMfaMechKeysItemAttestationAlgorithmsAnchor>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "objectDigest", default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<String>,
    #[serde(rename = "evidenceRecord", default, skip_serializing_if = "Option::is_none")]
    pub evidence_record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renewed_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renew_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "hashAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub tsa: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAndroidRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub checked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "certificationLevel", default, skip_serializing_if = "Option::is_none")]
    pub certification_level: Option<String>,
    #[serde(rename = "mdsStatus", default, skip_serializing_if = "Option::is_none")]
    pub mds_status: Option<String>,
    #[serde(rename = "mdsVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mds_version: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<UserDetailPageMfaMechKeysItemAttestationAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conveyance: Option<String>,
    #[serde(rename = "enterpriseDowngraded", default, skip_serializing_if = "Option::is_none")]
    pub enterprise_downgraded: Option<bool>,
    #[serde(rename = "attestationKeyId", default, skip_serializing_if = "Option::is_none")]
    pub attestation_key_id: Option<String>,
    #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none")]
    pub device_serial: Option<String>,
    #[serde(rename = "deviceSerialSource", default, skip_serializing_if = "Option::is_none")]
    pub device_serial_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<UserDetailPageMfaMechKeysItemAttestationEvidence>,
    #[serde(rename = "androidRevocation", default, skip_serializing_if = "Option::is_none")]
    pub android_revocation: Option<UserDetailPageMfaMechKeysItemAttestationAndroidRevocation>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemEnrolledBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationRefused {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItem {
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(rename = "publicKeyJwk", default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<UserDetailPageMfaMechKeysItemPublicKeyJwk>,
    #[serde(rename = "signCount", default, skip_serializing_if = "Option::is_none")]
    pub sign_count: Option<f64>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attachment: Option<Option<String>>,
    #[serde(rename = "userVerified", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub user_verified: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub algorithm: Option<Option<UserDetailPageMfaMechKeysItemAlgorithm>>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailPageMfaMechKeysItemAttestation>,
    #[serde(rename = "backupEligible", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_eligible: Option<Option<bool>>,
    #[serde(rename = "backupState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_state: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub discoverable: Option<Option<bool>>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_pin_length: Option<Option<f64>>,
    #[serde(rename = "userHandle", default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(rename = "enrolledBy", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<UserDetailPageMfaMechKeysItemEnrolledBy>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub provider: Option<Option<String>>,
    #[serde(rename = "providerSource", default, skip_serializing_if = "Option::is_none")]
    pub provider_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "upgradedAt", default, skip_serializing_if = "Option::is_none")]
    pub upgraded_at: Option<f64>,
    #[serde(rename = "upgradedTo", default, skip_serializing_if = "Option::is_none")]
    pub upgraded_to: Option<String>,
    #[serde(rename = "previousAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub previous_algorithm: Option<String>,
    #[serde(rename = "previousCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous_cose_alg: Option<Option<f64>>,
    #[serde(rename = "previousCredentialId", default, skip_serializing_if = "Option::is_none")]
    pub previous_credential_id: Option<String>,
    #[serde(rename = "upgradeMode", default, skip_serializing_if = "Option::is_none")]
    pub upgrade_mode: Option<String>,
    #[serde(rename = "possiblyReplacedBy", default, skip_serializing_if = "Option::is_none")]
    pub possibly_replaced_by: Option<String>,
    #[serde(rename = "possiblyReplacedAt", default, skip_serializing_if = "Option::is_none")]
    pub possibly_replaced_at: Option<f64>,
    #[serde(rename = "policyRefused", default, skip_serializing_if = "Option::is_none")]
    pub policy_refused: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "attestationRefused", default, skip_serializing_if = "Option::is_none")]
    pub attestation_refused: Option<UserDetailPageMfaMechKeysItemAttestationRefused>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechTotpDetail {
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unusable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechMailFactor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    #[serde(rename = "optedIn", default, skip_serializing_if = "Option::is_none")]
    pub opted_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechMfaRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "byUser", default, skip_serializing_if = "Option::is_none")]
    pub by_user: Option<bool>,
    #[serde(rename = "byRealm", default, skip_serializing_if = "Option::is_none")]
    pub by_realm: Option<bool>,
    #[serde(rename = "byAdministrator", default, skip_serializing_if = "Option::is_none")]
    pub by_administrator: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(rename = "exemptServiceAccount", default, skip_serializing_if = "Option::is_none")]
    pub exempt_service_account: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechPasswordResetLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMech {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "mfaKeys", default, skip_serializing_if = "Option::is_none")]
    pub mfa_keys: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageMfaMechKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
    pub totp_usable: Option<bool>,
    #[serde(rename = "totpDetail", default, skip_serializing_if = "Option::is_none")]
    pub totp_detail: Option<UserDetailPageMfaMechTotpDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<UserDetailPageMfaMechBackupCodes>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "mailFactor", default, skip_serializing_if = "Option::is_none")]
    pub mail_factor: Option<UserDetailPageMfaMechMailFactor>,
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub second_factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<bool>,
    #[serde(rename = "recoveryAdvised", default, skip_serializing_if = "Option::is_none")]
    pub recovery_advised: Option<bool>,
    #[serde(rename = "mfaRequirement", default, skip_serializing_if = "Option::is_none")]
    pub mfa_requirement: Option<UserDetailPageMfaMechMfaRequirement>,
    #[serde(rename = "passwordResetLink", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_link: Option<UserDetailPageMfaMechPasswordResetLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaTotp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<f64>,
    #[serde(rename = "secretBytes", default, skip_serializing_if = "Option::is_none")]
    pub secret_bytes: Option<f64>,
    #[serde(rename = "enrolmentTtlMs", default, skip_serializing_if = "Option::is_none")]
    pub enrolment_ttl_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaWebauthn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "rpName", default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(rename = "residentKey", default, skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(rename = "authenticatorAttachment", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<f64>,
    #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_pin_length: Option<Option<sts_model_base::unions::BoolOrNumber>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<String>>,
    #[serde(rename = "maxKeysPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_keys_per_person: Option<f64>,
    #[serde(rename = "primaryAllowed", default, skip_serializing_if = "Option::is_none")]
    pub primary_allowed: Option<bool>,
    #[serde(rename = "mfaAllowed", default, skip_serializing_if = "Option::is_none")]
    pub mfa_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usernameless: Option<bool>,
    #[serde(rename = "insecureAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub insecure_algorithms: Option<bool>,
    #[serde(rename = "pqcOnly", default, skip_serializing_if = "Option::is_none")]
    pub pqc_only: Option<bool>,
    #[serde(rename = "pqcAlongsideClassical", default, skip_serializing_if = "Option::is_none")]
    pub pqc_alongside_classical: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaRecovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
    #[serde(rename = "groupSize", default, skip_serializing_if = "Option::is_none")]
    pub group_size: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaAppPasswordsPasswordsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<Vec<String>>,
    #[serde(rename = "doorLabels", default, skip_serializing_if = "Option::is_none")]
    pub door_labels: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(rename = "lastUsedDoor", default, skip_serializing_if = "Option::is_none")]
    pub last_used_door: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaAppPasswords {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passwords: Option<Vec<UserDetailPageMfaAppPasswordsPasswordsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDoors {
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Vec<String>>,
    #[serde(rename = "passwordAloneDoors", default, skip_serializing_if = "Option::is_none")]
    pub password_alone_doors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaVerificationsVerificationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub recorded: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// The OpenID Connect for Identity Assurance `verification` element: a
    /// caller may post it whole as JSON, and a wallet or a certificate may
    /// supply it, so its evidence is that specification's to shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<serde_json::Value>,
    /// The verified claims and their values, as the OpenID Connect claim each
    /// is: a string for most, an object for `address`, a list for
    /// `nationalities`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaVerificationsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaVerifications {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "trustFrameworks", default, skip_serializing_if = "Option::is_none")]
    pub trust_frameworks: Option<Vec<String>>,
    #[serde(rename = "evidenceTypes", default, skip_serializing_if = "Option::is_none")]
    pub evidence_types: Option<Vec<String>>,
    #[serde(rename = "documentTypes", default, skip_serializing_if = "Option::is_none")]
    pub document_types: Option<Vec<String>>,
    #[serde(rename = "checkMethods", default, skip_serializing_if = "Option::is_none")]
    pub check_methods: Option<Vec<String>>,
    #[serde(rename = "electronicRecordTypes", default, skip_serializing_if = "Option::is_none")]
    pub electronic_record_types: Option<Vec<String>>,
    #[serde(rename = "attestationTypes", default, skip_serializing_if = "Option::is_none")]
    pub attestation_types: Option<Vec<String>>,
    #[serde(rename = "verifiableClaims", default, skip_serializing_if = "Option::is_none")]
    pub verifiable_claims: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifications: Option<Vec<UserDetailPageMfaVerificationsVerificationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<UserDetailPageMfaVerificationsPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItemAttestationRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub checked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItemAttestationFreshness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(rename = "verifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<UserDetailPageMfaDevicesDevicesItemKeysItemAttestationRevocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<UserDetailPageMfaDevicesDevicesItemKeysItemAttestationFreshness>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub added: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "addedBy", default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailPageMfaDevicesDevicesItemKeysItemAttestation>,
    /// A device key's public material as its kind carries it: a client's JWK, a
    /// certificate, or a WebAuthn credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(rename = "keyId", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemComplianceChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemStatusChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemRiskChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemEnrolment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemRememberedBrowser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<f64>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(rename = "secondFactorAt", default, skip_serializing_if = "Option::is_none")]
    pub second_factor_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageMfaDevicesDevicesItemKeysItem>>,
    #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
    pub key_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailPageMfaDevicesDevicesItemAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
    pub compliance_change: Option<UserDetailPageMfaDevicesDevicesItemComplianceChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
    pub status_change: Option<UserDetailPageMfaDevicesDevicesItemStatusChange>,
    #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
    pub risk_change: Option<UserDetailPageMfaDevicesDevicesItemRiskChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolment: Option<UserDetailPageMfaDevicesDevicesItemEnrolment>,
    #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
    pub native_sso: Option<bool>,
    #[serde(rename = "rememberedBrowser", default, skip_serializing_if = "Option::is_none")]
    pub remembered_browser: Option<UserDetailPageMfaDevicesDevicesItemRememberedBrowser>,
    #[serde(rename = "sessionLive", default, skip_serializing_if = "Option::is_none")]
    pub session_live: Option<bool>,
    #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_used: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<UserDetailPageMfaDevicesDevicesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSelfIssuedSubjectsItemLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSelfIssuedSubjectsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enrolled_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(rename = "provedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub proved_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<UserDetailPageMfaSelfIssuedSubjectsItemLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred: Option<bool>,
    #[serde(rename = "pinnedKeys", default, skip_serializing_if = "Option::is_none")]
    pub pinned_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSelfIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(rename = "signInEnabled", default, skip_serializing_if = "Option::is_none")]
    pub sign_in_enabled: Option<bool>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(rename = "subjectSyntaxTypes", default, skip_serializing_if = "Option::is_none")]
    pub subject_syntax_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<UserDetailPageMfaSelfIssuedSubjectsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemDeactivatedV1 {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailPageMfaPublishedDidsDidsItemDeactivated {
    V1(UserDetailPageMfaPublishedDidsDidsItemDeactivatedV1),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemPending {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemVersionsItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemVersionsItemAuthorizedByItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "keyThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    #[serde(rename = "versionId", default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemVersionsItem {
    #[serde(rename = "versionId", default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageMfaPublishedDidsDidsItemVersionsItemKeysItem>>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<Vec<UserDetailPageMfaPublishedDidsDidsItemVersionsItemAuthorizedByItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<String>,
    #[serde(rename = "documentUrl", default, skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub deactivated: Option<Option<UserDetailPageMfaPublishedDidsDidsItemDeactivated>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred: Option<bool>,
    #[serde(rename = "currentVersion", default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<UserDetailPageMfaPublishedDidsDidsItemPending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<UserDetailPageMfaPublishedDidsDidsItemVersionsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDids {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publishing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<String>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dids: Option<Vec<UserDetailPageMfaPublishedDidsDidsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaCertificatesCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialNumber", default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaCertificates {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaCertificatesCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSigningCertificatesItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSigning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaSigningCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<String>>,
    #[serde(rename = "defaultKeyAlg", default, skip_serializing_if = "Option::is_none")]
    pub default_key_alg: Option<String>,
    #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reasons: Option<Vec<String>>,
    #[serde(rename = "passwordMin", default, skip_serializing_if = "Option::is_none")]
    pub password_min: Option<f64>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMailStatusOffered {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMailStatus {
    #[serde(rename = "optedIn", default, skip_serializing_if = "Option::is_none")]
    pub opted_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<UserDetailPageMfaMailStatusOffered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<UserDetailPageMfaMailStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(rename = "audSubs", default, skip_serializing_if = "Option::is_none")]
    pub aud_subs: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mech: Option<UserDetailPageMfaMech>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<UserDetailPageMfaTotp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<UserDetailPageMfaWebauthn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<UserDetailPageMfaRecovery>,
    #[serde(rename = "appPasswords", default, skip_serializing_if = "Option::is_none")]
    pub app_passwords: Option<UserDetailPageMfaAppPasswords>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<UserDetailPageMfaDoors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifications: Option<UserDetailPageMfaVerifications>,
    #[serde(rename = "inventsClaimValues", default, skip_serializing_if = "Option::is_none")]
    pub invents_claim_values: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<UserDetailPageMfaDevices>,
    #[serde(rename = "selfIssued", default, skip_serializing_if = "Option::is_none")]
    pub self_issued: Option<UserDetailPageMfaSelfIssued>,
    #[serde(rename = "publishedDids", default, skip_serializing_if = "Option::is_none")]
    pub published_dids: Option<UserDetailPageMfaPublishedDids>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<UserDetailPageMfaCertificates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<UserDetailPageMfaSigning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<UserDetailPageMfaMail>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageFieldGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageDelegationDelegateV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailPageDelegationDelegate {
    V1(UserDetailPageDelegationDelegateV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageDelegationGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageDelegation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub delegate: Option<Option<UserDetailPageDelegationDelegate>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<UserDetailPageDelegationGroupsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemKeysItemCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemKeysItemChainItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<UserDetailPageKeyPairsPurposesItemKeysItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<UserDetailPageKeyPairsPurposesItemKeysItemChainItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageKeyPairsPurposesItemKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
    pub at_cap: Option<bool>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(rename = "effectiveIssuers", default, skip_serializing_if = "Option::is_none")]
    pub effective_issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserDetailPageKeyPairsPurposesItemAttributes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsCaKeyAlgorithmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "tlsUsable", default, skip_serializing_if = "Option::is_none")]
    pub tls_usable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsCa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "leafLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub leaf_lifetime_days: Option<f64>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<UserDetailPageKeyPairsCaKeyAlgorithmsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<UserDetailPageKeyPairsPurposesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<UserDetailPageKeyPairsCa>,
    #[serde(rename = "sealsAtRest", default, skip_serializing_if = "Option::is_none")]
    pub seals_at_rest: Option<bool>,
    #[serde(rename = "selfService", default, skip_serializing_if = "Option::is_none")]
    pub self_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageServiceAccountRules {
    #[serde(rename = "requiresOwner", default, skip_serializing_if = "Option::is_none")]
    pub requires_owner: Option<bool>,
    #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
    pub max_owners: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageServiceProvidersItem {
    #[serde(rename = "fedId", default, skip_serializing_if = "Option::is_none")]
    pub fed_id: Option<String>,
    #[serde(rename = "fedPeer", default, skip_serializing_if = "Option::is_none")]
    pub fed_peer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "riskAsked", default, skip_serializing_if = "Option::is_none")]
    pub risk_asked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<UserDetailPageCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub back: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "blocksPerPage", default, skip_serializing_if = "Option::is_none")]
    pub blocks_per_page: Option<f64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<f64>,
    #[serde(rename = "maxEventsPerUser", default, skip_serializing_if = "Option::is_none")]
    pub max_events_per_user: Option<f64>,
    #[serde(rename = "directoryLoaded", default, skip_serializing_if = "Option::is_none")]
    pub directory_loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<UserDetailPageMfa>,
    #[serde(rename = "fieldGroups", default, skip_serializing_if = "Option::is_none")]
    pub field_groups: Option<Vec<UserDetailPageFieldGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<UserDetailPageDelegation>,
    #[serde(rename = "keyPairs", default, skip_serializing_if = "Option::is_none")]
    pub key_pairs: Option<UserDetailPageKeyPairs>,
    #[serde(rename = "serviceAccountRules", default, skip_serializing_if = "Option::is_none")]
    pub service_account_rules: Option<UserDetailPageServiceAccountRules>,
    #[serde(rename = "serviceProviders", default, skip_serializing_if = "Option::is_none")]
    pub service_providers: Option<Vec<UserDetailPageServiceProvidersItem>>,
}

/// One identity: the names it has been seen under, how it authenticated, every
/// sign-on session it holds with the tokens issued on each, and its directory
/// entry.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDetailUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<UserDetailServiceAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<UserDetailRisk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<UserDetailFactors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<UserDetailSessionsItem>>,
    #[serde(rename = "sessionsPaging", default, skip_serializing_if = "Option::is_none")]
    pub sessions_paging: Option<UserDetailSessionsPaging>,
    #[serde(rename = "tokensOnEndedSessions", default, skip_serializing_if = "Option::is_none")]
    pub tokens_on_ended_sessions: Option<Vec<UserDetailTokensOnEndedSessionsItem>>,
    #[serde(rename = "tokensOnEndedSessionsPaging", default, skip_serializing_if = "Option::is_none")]
    pub tokens_on_ended_sessions_paging: Option<UserDetailTokensOnEndedSessionsPaging>,
    #[serde(rename = "tokensWithNoSession", default, skip_serializing_if = "Option::is_none")]
    pub tokens_with_no_session: Option<Vec<UserDetailTokensWithNoSessionItem>>,
    #[serde(rename = "tokensWithNoSessionPaging", default, skip_serializing_if = "Option::is_none")]
    pub tokens_with_no_session_paging: Option<UserDetailTokensWithNoSessionPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<UserDetailArtifactsItem>>,
    #[serde(rename = "artifactsPaging", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_paging: Option<UserDetailArtifactsPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<UserDetailLdap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<UserDetailCredentials>,
    #[serde(rename = "federationLinks", default, skip_serializing_if = "Option::is_none")]
    pub federation_links: Option<Vec<UserDetailFederationLinksItem>>,
    #[serde(rename = "federationLinksPaging", default, skip_serializing_if = "Option::is_none")]
    pub federation_links_paging: Option<UserDetailFederationLinksPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kerberos: Option<UserDetailKerberos>,
    #[serde(rename = "attributeEditor", default, skip_serializing_if = "Option::is_none")]
    pub attribute_editor: Option<UserDetailAttributeEditor>,
    #[serde(rename = "gnapGrants", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants: Option<Vec<UserDetailGnapGrantsItem>>,
    #[serde(rename = "gnapGrantsPaging", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants_paging: Option<UserDetailGnapGrantsPaging>,
    #[serde(rename = "gnapGrantsCells", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants_cells: Option<UserDetailGnapGrantsCells>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uma: Option<UserDetailUma>,
    #[serde(rename = "authenticationEvents", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events: Option<Vec<UserDetailAuthenticationEventsItem>>,
    #[serde(rename = "authenticationEventsPaging", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_paging: Option<UserDetailAuthenticationEventsPaging>,
    #[serde(rename = "authenticationEventsMatched", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_matched: Option<f64>,
    #[serde(rename = "authenticationEventsKnownActors", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_known_actors: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "authenticationEventsLog", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_log: Option<UserDetailAuthenticationEventsLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<UserDetailPage>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserInfoClaimSetsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<UserInfoClaimSetsProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestRequestableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouped: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestDirectParameter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spellings: Option<Vec<String>>,
    #[serde(rename = "malformedIsRefused", default, skip_serializing_if = "Option::is_none")]
    pub malformed_is_refused: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestPreviewReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// The claims request as a caller typed it, parsed: OIDC Core 5.5 keys it
    /// by the claims they ask for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<serde_json::Value>,
    #[serde(rename = "ignoredMembers", default, skip_serializing_if = "Option::is_none")]
    pub ignored_members: Option<Vec<String>>,
    #[serde(rename = "idTokenNames", default, skip_serializing_if = "Option::is_none")]
    pub id_token_names: Option<Vec<String>>,
    /// The claims one person would be issued for that request, keyed by the
    /// names it asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<UserInfoClaimSetsClaimsRequestPreviewReportItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolvable: Option<Vec<String>>,
    #[serde(rename = "essentialAndAbsent", default, skip_serializing_if = "Option::is_none")]
    pub essential_and_absent: Option<Vec<String>>,
    #[serde(rename = "valueMismatches", default, skip_serializing_if = "Option::is_none")]
    pub value_mismatches: Option<Vec<String>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(rename = "maxClaims", default, skip_serializing_if = "Option::is_none")]
    pub max_claims: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestable: Option<Vec<UserInfoClaimSetsClaimsRequestRequestableItem>>,
    #[serde(rename = "fromTheSignIn", default, skip_serializing_if = "Option::is_none")]
    pub from_the_sign_in: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<Vec<String>>,
    #[serde(rename = "notEnforced", default, skip_serializing_if = "Option::is_none")]
    pub not_enforced: Option<Vec<String>>,
    #[serde(rename = "directParameter", default, skip_serializing_if = "Option::is_none")]
    pub direct_parameter: Option<UserInfoClaimSetsClaimsRequestDirectParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<UserInfoClaimSetsClaimsRequestPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsAttributeCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub schema: Option<Option<String>>,
    /// Whether it is ticked, by claim set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub syntax: Option<Option<String>>,
    #[serde(rename = "pacClaimId", default, skip_serializing_if = "Option::is_none")]
    pub pac_claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItemClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItemAttributeReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItemAttributeClaimPreviewItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<bool>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<UserInfoClaimSetsSetsItemClaimsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    /// The claims one person would be issued, keyed and nested by the claim
    /// names the catalogue and an administrator chose.
    #[serde(rename = "attributeClaims", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claims: Option<serde_json::Value>,
    #[serde(rename = "attributeReport", default, skip_serializing_if = "Option::is_none")]
    pub attribute_report: Option<Vec<UserInfoClaimSetsSetsItemAttributeReportItem>>,
    #[serde(rename = "attributeClaimPreview", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claim_preview: Option<Vec<UserInfoClaimSetsSetsItemAttributeClaimPreviewItem>>,
    /// Partners withholding it, by claim.
    #[serde(rename = "withheldFrom", default, skip_serializing_if = "Option::is_none")]
    pub withheld_from: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsAttributeChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// By directory attribute.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsGroupsPreviewGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rule: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Vec<String>>,
    #[serde(rename = "viaMemberOf", default, skip_serializing_if = "Option::is_none")]
    pub via_member_of: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsGroupsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<UserInfoClaimSetsGroupsPreviewGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsGroups {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<UserInfoClaimSetsGroupsPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsWithholdingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSets {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<UserInfoClaimSetsProtocolEndpointsItem>>,
    #[serde(rename = "reservedJwtClaims", default, skip_serializing_if = "Option::is_none")]
    pub reserved_jwt_claims: Option<Vec<String>>,
    #[serde(rename = "claimsRequest", default, skip_serializing_if = "Option::is_none")]
    pub claims_request: Option<UserInfoClaimSetsClaimsRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(rename = "inventedEmail", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub invented_email: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<Vec<String>>,
    #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub attribute_catalogue: Option<Vec<UserInfoClaimSetsAttributeCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<UserInfoClaimSetsSetsItem>>,
    #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
    pub attribute_choices: Option<Vec<UserInfoClaimSetsAttributeChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<UserInfoClaimSetsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<UserInfoClaimSetsGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withholding: Option<Vec<UserInfoClaimSetsWithholdingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLdifExportAnswerFilesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLdifExportAnswer {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(rename = "leftOut", default, skip_serializing_if = "Option::is_none")]
    pub left_out: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldif: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<UserLdifExportAnswerFilesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLdifImportAnswer {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<String>>,
    #[serde(rename = "kerberosKeys", default, skip_serializing_if = "Option::is_none")]
    pub kerberos_keys: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListFactors {
    #[serde(rename = "withSecond", default, skip_serializing_if = "Option::is_none")]
    pub with_second: Option<f64>,
    #[serde(rename = "withTotp", default, skip_serializing_if = "Option::is_none")]
    pub with_totp: Option<f64>,
    #[serde(rename = "withKeys", default, skip_serializing_if = "Option::is_none")]
    pub with_keys: Option<f64>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "passwordOnly", default, skip_serializing_if = "Option::is_none")]
    pub password_only: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<f64>,
    #[serde(rename = "noCredential", default, skip_serializing_if = "Option::is_none")]
    pub no_credential: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListDirectoryCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<f64>,
    #[serde(rename = "withSecond", default, skip_serializing_if = "Option::is_none")]
    pub with_second: Option<f64>,
    #[serde(rename = "withTotp", default, skip_serializing_if = "Option::is_none")]
    pub with_totp: Option<f64>,
    #[serde(rename = "withKeys", default, skip_serializing_if = "Option::is_none")]
    pub with_keys: Option<f64>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<f64>,
    #[serde(rename = "withPassword", default, skip_serializing_if = "Option::is_none")]
    pub with_password: Option<f64>,
    #[serde(rename = "passwordOnly", default, skip_serializing_if = "Option::is_none")]
    pub password_only: Option<f64>,
    #[serde(rename = "noWayIn", default, skip_serializing_if = "Option::is_none")]
    pub no_way_in: Option<f64>,
    #[serde(rename = "signedInHere", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub signed_in_here: Option<Option<f64>>,
    #[serde(rename = "neverSignedInHere", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub never_signed_in_here: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFormsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemRealmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemProtocolsItemMethodsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<UserListUsersItemProtocolsItemMethodsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserListUsersItemEventsItemAmr {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<UserListUsersItemEventsItemAmr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemArtifactKindsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFactorsTotpDetail {
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unusable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFactorsBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFactors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
    pub in_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "mfaKeys", default, skip_serializing_if = "Option::is_none")]
    pub mfa_keys: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
    pub totp_usable: Option<bool>,
    #[serde(rename = "totpDetail", default, skip_serializing_if = "Option::is_none")]
    pub totp_detail: Option<UserListUsersItemFactorsTotpDetail>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<UserListUsersItemFactorsBackupCodes>,
    #[serde(rename = "recoveryAdvised", default, skip_serializing_if = "Option::is_none")]
    pub recovery_advised: Option<bool>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub second_factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forms: Option<Vec<UserListUsersItemFormsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<UserListUsersItemRealmsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<UserListUsersItemProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
    pub is_client: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "knownBy", default, skip_serializing_if = "Option::is_none")]
    pub known_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<UserListUsersItemEventsItem>>,
    #[serde(rename = "eventsForgotten", default, skip_serializing_if = "Option::is_none")]
    pub events_forgotten: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<UserListUsersItemTokens>,
    #[serde(rename = "artifactKinds", default, skip_serializing_if = "Option::is_none")]
    pub artifact_kinds: Option<Vec<UserListUsersItemArtifactKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<f64>,
    #[serde(rename = "lastActivityAt", default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<UserListUsersItemFactors>,
    #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
    pub in_directory: Option<bool>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "liveSessions", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub live_sessions: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

/// Everyone this service has authenticated, united with at most `scanLimit` of
/// the people the directory defines.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<f64>,
    #[serde(rename = "authenticatedHere", default, skip_serializing_if = "Option::is_none")]
    pub authenticated_here: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<UserListFactors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capped: Option<bool>,
    #[serde(rename = "scanLimit", default, skip_serializing_if = "Option::is_none")]
    pub scan_limit: Option<f64>,
    #[serde(rename = "directoryPeople", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub directory_people: Option<Option<f64>>,
    #[serde(rename = "directoryCounts", default, skip_serializing_if = "Option::is_none")]
    pub directory_counts: Option<UserListDirectoryCounts>,
    #[serde(rename = "directoryCountedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub directory_counted_at: Option<Option<String>>,
    #[serde(rename = "directoryCountsKeptFor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub directory_counts_kept_for: Option<Option<f64>>,
    #[serde(rename = "registryCap", default, skip_serializing_if = "Option::is_none")]
    pub registry_cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<UserListFilter>,
    #[serde(rename = "serviceAccounts", default, skip_serializing_if = "Option::is_none")]
    pub service_accounts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<UserListPaging>,
    #[serde(rename = "withActiveSession", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub with_active_session: Option<Option<f64>>,
    #[serde(rename = "personFieldCount", default, skip_serializing_if = "Option::is_none")]
    pub person_field_count: Option<f64>,
    #[serde(rename = "newUserContainer", default, skip_serializing_if = "Option::is_none")]
    pub new_user_container: Option<String>,
    #[serde(rename = "registryKeeps", default, skip_serializing_if = "Option::is_none")]
    pub registry_keeps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<UserListUsersItem>>,
}

pub type WithAdditionalPropertiesPropertiesPage2 = Vec<crate::WithGroupSettingsAdditionalProperties2>;

pub type WithAdditionalPropertiesPropertiesPartnerRealm = Vec<crate::WithKindLevelText>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithConfigFileDefaultsFilePersistsAppconfig {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none")]
    pub defaults_file: Option<String>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

pub type WithConfigFileDefaultsFilePersistsAppconfig2 = Vec<crate::WithGroupSettingsConfigFile2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithConfigFileDefaultsFilePersistsAppconfig3 {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

pub type WithConfigFileDefaultsFilePersistsAppconfig4 = Vec<crate::WithGroupSettingsConfigFile4>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithConfigFileDefaultsFilePersistsAppconfig5 {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

pub type WithGroupSettingsAdditionalProperties = Vec<crate::WithKeyGroupLabel4>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithGroupSettingsAdditionalProperties2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithGroupSettingsAdditionalProperties>,
}

pub type WithGroupSettingsConfigFile = Vec<crate::WithKeyGroupLabel>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithGroupSettingsConfigFile2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithGroupSettingsConfigFile>,
}

pub type WithGroupSettingsConfigFile3 = Vec<crate::WithKeyGroupLabel3>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithGroupSettingsConfigFile4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithGroupSettingsConfigFile3>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabelValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabelEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabelLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabelDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyGroupLabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<crate::WithOnlyWhileOnAloneWhileOnKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<WithKeyGroupLabelValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<WithKeyGroupLabelEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<WithKeyGroupLabelLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<WithKeyGroupLabelDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel3Value {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel3Default {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyGroupLabel3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<crate::RulesKindOnlyWhileOnAloneWhileOn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<WithKeyGroupLabel3Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<WithKeyGroupLabel3Default>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel4Value {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel4Env {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel4LegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel4Default {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyGroupLabel4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<crate::WithOnlyWhileOnAloneWhileOnKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<WithKeyGroupLabel4Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restart_reason: Option<Option<String>>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub edit_refusal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<WithKeyGroupLabel4Env>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<WithKeyGroupLabel4LegacyEnv>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<WithKeyGroupLabel4Default>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKindLevelText {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// What the sentence is filled from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithMethodEndpointurlAdditionalProperties {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<sts_model_management_components_1::ValueDocumentPartnerPublishedAnswered>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOnlyWhileOnAloneWhileOnKeyOnlyWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOnlyWhileOnAloneWhileOnKeyAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOnlyWhileOnAloneWhileOnKey {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<WithOnlyWhileOnAloneWhileOnKeyOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<WithOnlyWhileOnAloneWhileOnKeyAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPreviousHeldKvnoPrevious {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub retired_at: Option<Option<String>>,
    #[serde(rename = "acceptedUntil", default, skip_serializing_if = "Option::is_none")]
    pub accepted_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPreviousHeldKvno {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<WithPreviousHeldKvnoPrevious>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "setAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub set_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}
