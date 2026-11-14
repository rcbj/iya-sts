// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/domain/ (#1390, #444). Do not edit: change the
// model and run tests/tools/regenerate-model-docs.sh.
// tests/model_domain.js fails when this differs.

// The domain concepts, one struct each, as `common/domain_classes.ts`
// holds them for the Node service. Included by sts-model's lib.rs.

use crate::{FieldSource, MadeFrom};

/// Something this service issues to or accepts from, in any protocol.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub identifier: String,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "homePage", default, skip_serializing_if = "Option::is_none")]
    pub home_page: Option<String>,
    #[serde(rename = "allowedProtocols", default, skip_serializing_if = "Option::is_none")]
    pub allowed_protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<SamlServiceProvider>,
    #[serde(rename = "wsFederation", default, skip_serializing_if = "Option::is_none")]
    pub ws_federation: Option<WsFederationRelyingParty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "launchProtocol", default, skip_serializing_if = "Option::is_none")]
    pub launch_protocol: Option<String>,
    #[serde(rename = "corsOrigin", default, skip_serializing_if = "Option::is_none")]
    pub cors_origin: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Vec<String>>,
    #[serde(rename = "authorizationServer", default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<String>,
    #[serde(rename = "lastSession", default, skip_serializing_if = "Option::is_none")]
    pub last_session: Option<String>,
    #[serde(rename = "lastUser", default, skip_serializing_if = "Option::is_none")]
    pub last_user: Option<String>,
    #[serde(rename = "registeredBy", default, skip_serializing_if = "Option::is_none")]
    pub registered_by: Option<String>,
    #[serde(rename = "federationRegistration", default, skip_serializing_if = "Option::is_none")]
    pub federation_registration: Option<String>,
    #[serde(rename = "federationExpiresAt", default, skip_serializing_if = "Option::is_none")]
    pub federation_expires_at: Option<String>,
    #[serde(rename = "federationTrustAnchor", default, skip_serializing_if = "Option::is_none")]
    pub federation_trust_anchor: Option<String>,
    #[serde(rename = "redirectUriObserved", default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri_observed: Option<Vec<String>>,
    #[serde(rename = "returnAddressObserved", default, skip_serializing_if = "Option::is_none")]
    pub return_address_observed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Vec<String>>,
    #[serde(rename = "stsOwnerProtected", default, skip_serializing_if = "Option::is_none")]
    pub sts_owner_protected: Option<String>,
    #[serde(rename = "authzenAttribute", default, skip_serializing_if = "Option::is_none")]
    pub authzen_attribute: Option<Vec<String>>,
    #[serde(rename = "authzenApplication", default, skip_serializing_if = "Option::is_none")]
    pub authzen_application: Option<Vec<String>>,
    #[serde(rename = "authzenCallbackUri", default, skip_serializing_if = "Option::is_none")]
    pub authzen_callback_uri: Option<Vec<String>>,
    #[serde(rename = "softwareStatementIssuer", default, skip_serializing_if = "Option::is_none")]
    pub software_statement_issuer: Option<String>,
    #[serde(rename = "softwareStatementTrusted", default, skip_serializing_if = "Option::is_none")]
    pub software_statement_trusted: Option<String>,
    #[serde(rename = "softwareStatementPublisher", default, skip_serializing_if = "Option::is_none")]
    pub software_statement_publisher: Option<String>,
    #[serde(rename = "requiredRole", default, skip_serializing_if = "Option::is_none")]
    pub required_role: Option<Vec<String>>,
    #[serde(rename = "allowedToDelegateTo", default, skip_serializing_if = "Option::is_none")]
    pub allowed_to_delegate_to: Option<Vec<String>>,
    #[serde(rename = "allowedToActOnBehalfOf", default, skip_serializing_if = "Option::is_none")]
    pub allowed_to_act_on_behalf_of: Option<Vec<String>>,
    #[serde(rename = "delegationSubjectGroup", default, skip_serializing_if = "Option::is_none")]
    pub delegation_subject_group: Option<Vec<String>>,
    #[serde(rename = "delegationSemantics", default, skip_serializing_if = "Option::is_none")]
    pub delegation_semantics: Option<Vec<String>>,
    #[serde(rename = "defaultDelegationSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_delegation_semantics: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<String>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(rename = "groupsClaim", default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    #[serde(rename = "groupsClaimName", default, skip_serializing_if = "Option::is_none")]
    pub groups_claim_name: Option<String>,
    #[serde(rename = "groupsClaimValue", default, skip_serializing_if = "Option::is_none")]
    pub groups_claim_value: Option<String>,
    #[serde(rename = "groupsClaimFromMemberOf", default, skip_serializing_if = "Option::is_none")]
    pub groups_claim_from_member_of: Option<String>,
    #[serde(rename = "enrolledCertificate", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_certificate: Option<Vec<String>>,
    #[serde(rename = "enrolledPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_private_key: Option<Vec<String>>,
    #[serde(rename = "acmeEabKey", default, skip_serializing_if = "Option::is_none")]
    pub acme_eab_key: Option<Vec<String>>,
    #[serde(rename = "scepChallenge", default, skip_serializing_if = "Option::is_none")]
    pub scep_challenge: Option<Vec<String>>,
    #[serde(rename = "certificateHostName", default, skip_serializing_if = "Option::is_none")]
    pub certificate_host_name: Option<Vec<String>>,
    #[serde(rename = "registrationJson", default, skip_serializing_if = "Option::is_none")]
    pub registration_json: Option<String>,
    #[serde(rename = "registrationAccessToken", default, skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(rename = "federationPartnerId", default, skip_serializing_if = "Option::is_none")]
    pub federation_partner_id: Option<Vec<String>>,
    #[serde(rename = "ldapBindDn", default, skip_serializing_if = "Option::is_none")]
    pub ldap_bind_dn: Option<Vec<String>>,
    #[serde(rename = "enrollMaxCertificates", default, skip_serializing_if = "Option::is_none")]
    pub enroll_max_certificates: Option<String>,
    #[serde(rename = "spiffeWorkloadId", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_workload_id: Option<Vec<String>>,
    #[serde(rename = "federationRelationship", default, skip_serializing_if = "Option::is_none")]
    pub federation_relationship: Option<Vec<String>>,
    #[serde(rename = "federationAutoRedirect", default, skip_serializing_if = "Option::is_none")]
    pub federation_auto_redirect: Option<String>,
    #[serde(rename = "authnPolicy", default, skip_serializing_if = "Option::is_none")]
    pub authn_policy: Option<String>,
    #[serde(rename = "passkeyPolicy", default, skip_serializing_if = "Option::is_none")]
    pub passkey_policy: Option<String>,
    #[serde(rename = "localePolicy", default, skip_serializing_if = "Option::is_none")]
    pub locale_policy: Option<String>,
    #[serde(rename = "passwordPolicy", default, skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<String>,
    #[serde(rename = "postLoginPolicy", default, skip_serializing_if = "Option::is_none")]
    pub post_login_policy: Option<String>,
    #[serde(rename = "fgaPolicy", default, skip_serializing_if = "Option::is_none")]
    pub fga_policy: Option<String>,
    #[serde(rename = "fgaEnforced", default, skip_serializing_if = "Option::is_none")]
    pub fga_enforced: Option<String>,
    #[serde(rename = "umaOwnsResources", default, skip_serializing_if = "Option::is_none")]
    pub uma_owns_resources: Option<String>,
    #[serde(rename = "verifiableCredentialPartner", default, skip_serializing_if = "Option::is_none")]
    pub verifiable_credential_partner: Option<VerifiableCredentialPartner>,
    #[serde(rename = "wsTrustRelyingParty", default, skip_serializing_if = "Option::is_none")]
    pub ws_trust_relying_party: Option<WsTrustRelyingParty>,
    #[serde(rename = "kerberosService", default, skip_serializing_if = "Option::is_none")]
    pub kerberos_service: Option<KerberosService>,
    #[serde(rename = "gnapClient", default, skip_serializing_if = "Option::is_none")]
    pub gnap_client: Option<GnapClient>,
    #[serde(rename = "scimProvisioningTarget", default, skip_serializing_if = "Option::is_none")]
    pub scim_provisioning_target: Option<ScimProvisioningTarget>,
    #[serde(rename = "certificateEnrollment", default, skip_serializing_if = "Option::is_none")]
    pub certificate_enrollment: Option<CertificateEnrollment>,
    #[serde(rename = "secretDestination", default, skip_serializing_if = "Option::is_none")]
    pub secret_destination: Option<SecretDestination>,
    #[serde(rename = "sharedSignalsReceiver", default, skip_serializing_if = "Option::is_none")]
    pub shared_signals_receiver: Option<SharedSignalsReceiver>,
}

impl Application {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "identifier",
            attribute: Some("appIdentifier"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "displayName",
            attribute: Some("appName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "homePage",
            attribute: Some("appHomePageUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedProtocols",
            attribute: Some("appAllowedProtocol"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registered",
            attribute: Some("appRegistered"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "firstSeen",
            attribute: Some("appFirstSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSeen",
            attribute: Some("appLastSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "oauth",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "saml",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "wsFederation",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "cn",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "launchProtocol",
            attribute: Some("appLaunchProtocol"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "corsOrigin",
            attribute: Some("appCorsOrigin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "kind",
            attribute: Some("appKind"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "protocol",
            attribute: Some("appProtocol"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationServer",
            attribute: Some("appAuthorizationServer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authentications",
            attribute: Some("appAuthentications"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sessions",
            attribute: Some("appSessions"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "users",
            attribute: Some("appUsers"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSession",
            attribute: Some("appLastSession"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastUser",
            attribute: Some("appLastUser"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registeredBy",
            attribute: Some("appRegisteredBy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationRegistration",
            attribute: Some("appFederationRegistration"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationExpiresAt",
            attribute: Some("appFederationExpiresAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationTrustAnchor",
            attribute: Some("appFederationTrustAnchor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "redirectUriObserved",
            attribute: Some("appRedirectUriObserved"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "returnAddressObserved",
            attribute: Some("appReturnAddressObserved"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "owner",
            attribute: Some("appOwner"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsOwnerProtected",
            attribute: Some("stsOwnerProtected"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authzenAttribute",
            attribute: Some("authzenAttribute"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authzenApplication",
            attribute: Some("appAuthzenApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authzenCallbackUri",
            attribute: Some("appAuthzenCallbackUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "softwareStatementIssuer",
            attribute: Some("appSoftwareStatementIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "softwareStatementTrusted",
            attribute: Some("appSoftwareStatementTrusted"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "softwareStatementPublisher",
            attribute: Some("appSoftwareStatementPublisher"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requiredRole",
            attribute: Some("appRequiredRole"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedToDelegateTo",
            attribute: Some("appAllowedToDelegateTo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedToActOnBehalfOf",
            attribute: Some("appAllowedToActOnBehalfOf"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "delegationSubjectGroup",
            attribute: Some("appDelegationSubjectGroup"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "delegationSemantics",
            attribute: Some("appDelegationSemantics"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultDelegationSemantics",
            attribute: Some("appDefaultDelegationSemantics"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "notDelegated",
            attribute: Some("appNotDelegated"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mayAct",
            attribute: Some("appMayAct"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "groupsClaim",
            attribute: Some("appGroupsClaim"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "groupsClaimName",
            attribute: Some("appGroupsClaimName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "groupsClaimValue",
            attribute: Some("appGroupsClaimValue"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "groupsClaimFromMemberOf",
            attribute: Some("appGroupsClaimFromMemberOf"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enrolledCertificate",
            attribute: Some("appEnrolledCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enrolledPrivateKey",
            attribute: Some("appEnrolledPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "acmeEabKey",
            attribute: Some("appAcmeEabKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scepChallenge",
            attribute: Some("appScepChallenge"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateHostName",
            attribute: Some("appCertificateHostName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registrationJson",
            attribute: Some("appRegistrationJson"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registrationAccessToken",
            attribute: Some("appRegistrationAccessToken"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationPartnerId",
            attribute: Some("federationPartnerId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "ldapBindDn",
            attribute: Some("ldapBindDn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enrollMaxCertificates",
            attribute: Some("enrollMaxCertificates"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffeWorkloadId",
            attribute: Some("spiffeWorkloadId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationRelationship",
            attribute: Some("appFederationRelationship"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationAutoRedirect",
            attribute: Some("appFederationAutoRedirect"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authnPolicy",
            attribute: Some("appAuthnPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passkeyPolicy",
            attribute: Some("appPasskeyPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "localePolicy",
            attribute: Some("appLocalePolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordPolicy",
            attribute: Some("appPasswordPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "postLoginPolicy",
            attribute: Some("appPostLoginPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "fgaPolicy",
            attribute: Some("appFgaPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "fgaEnforced",
            attribute: Some("appFgaEnforced"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "umaOwnsResources",
            attribute: Some("umaOwnsResources"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "verifiableCredentialPartner",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "wsTrustRelyingParty",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "kerberosService",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "gnapClient",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "scimProvisioningTarget",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "certificateEnrollment",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "secretDestination",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
        FieldSource {
            name: "sharedSignalsReceiver",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: true,
        },
    ];
}

/// What every person in a realm must hold.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(rename = "singleValued", default, skip_serializing_if = "Option::is_none")]
    pub single_valued: Option<bool>,
    #[serde(rename = "portalVisible", default, skip_serializing_if = "Option::is_none")]
    pub portal_visible: Option<bool>,
    #[serde(rename = "portalEditable", default, skip_serializing_if = "Option::is_none")]
    pub portal_editable: Option<bool>,
    #[serde(rename = "policyPrecedence", default, skip_serializing_if = "Option::is_none")]
    pub policy_precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

impl AttributePolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.attributes");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "required",
            attribute: Some("stsAttributeRequired"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "label",
            attribute: Some("stsAttributeLabel"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "syntax",
            attribute: Some("stsAttributeSyntax"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "singleValued",
            attribute: Some("stsAttributeSingleValued"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "portalVisible",
            attribute: Some("stsAttributePortalVisible"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "portalEditable",
            attribute: Some("stsAttributePortalEditable"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policyPrecedence",
            attribute: Some("stsAttributePolicyPrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policy",
            attribute: Some("stsAttributePolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// An operator database a realm reads attributes from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<Vec<String>>,
}

impl AttributeSource {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("attributeSource");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "cn",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "data",
            attribute: Some("stsAttributeSourceData"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "d",
            attribute: Some("stsAttributeSourced"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "seen",
            attribute: Some("stsAttributeSourceSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// One thing that happened, as the realm's audit log records it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: i64,
    pub at: i64,
    pub category: String,
    pub action: String,
    pub outcome: String,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "actorForm", default, skip_serializing_if = "Option::is_none")]
    pub actor_form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Map<String, serde_json::Value>>,
}

impl AuditEvent {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Record("common/audit.js audit()");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "sequence",
            attribute: None,
            on: None,
            key: Some("seq"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "at",
            attribute: None,
            on: None,
            key: Some("at"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "category",
            attribute: None,
            on: None,
            key: Some("category"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "action",
            attribute: None,
            on: None,
            key: Some("action"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "outcome",
            attribute: None,
            on: None,
            key: Some("outcome"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "errorCode",
            attribute: None,
            on: None,
            key: Some("errorCode"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "actor",
            attribute: None,
            on: None,
            key: Some("actor"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "target",
            attribute: None,
            on: None,
            key: Some("target"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "summary",
            attribute: None,
            on: None,
            key: Some("summary"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "origin",
            attribute: None,
            on: None,
            key: Some("origin"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "actorForm",
            attribute: None,
            on: None,
            key: Some("actorForm"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "protocol",
            attribute: None,
            on: None,
            key: Some("protocol"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "channel",
            attribute: None,
            on: None,
            key: Some("channel"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "address",
            attribute: None,
            on: None,
            key: Some("address"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "detail",
            attribute: None,
            on: None,
            key: Some("detail"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// One act of proving who somebody is, recorded on the session it happened in.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationEvent {
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(rename = "assuranceLevel", default, skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<String>,
    pub protocol: String,
    pub authenticated: bool,
    #[serde(rename = "authorityKind", default, skip_serializing_if = "Option::is_none")]
    pub authority_kind: Option<String>,
}

impl AuthenticationEvent {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Record("authn/authn.ts authenticationEvent()");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "at",
            attribute: None,
            on: None,
            key: Some("at"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "methods",
            attribute: None,
            on: None,
            key: Some("amr"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assuranceLevel",
            attribute: None,
            on: None,
            key: Some("acr"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "protocol",
            attribute: None,
            on: None,
            key: Some("via"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authenticated",
            attribute: None,
            on: None,
            key: Some("authenticated"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorityKind",
            attribute: None,
            on: None,
            key: Some("authority.kind"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Which mechanisms a sign-in may use.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationPolicy {
    #[serde(rename = "requireSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub require_second_factor: Option<String>,
    #[serde(rename = "requireSecondFactorForAdministrators", default, skip_serializing_if = "Option::is_none")]
    pub require_second_factor_for_administrators: Option<String>,
    #[serde(rename = "passwordPrimary", default, skip_serializing_if = "Option::is_none")]
    pub password_primary: Option<bool>,
    #[serde(rename = "passwordSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub password_second_factor: Option<bool>,
    #[serde(rename = "passkeyPrimary", default, skip_serializing_if = "Option::is_none")]
    pub passkey_primary: Option<bool>,
    #[serde(rename = "securityKeySecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub security_key_second_factor: Option<bool>,
    #[serde(rename = "totpSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub totp_second_factor: Option<bool>,
    #[serde(rename = "recoveryCodeSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub recovery_code_second_factor: Option<bool>,
    #[serde(rename = "emailCodePrimary", default, skip_serializing_if = "Option::is_none")]
    pub email_code_primary: Option<bool>,
    #[serde(rename = "emailCodeSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub email_code_second_factor: Option<bool>,
    #[serde(rename = "emailLinkPrimary", default, skip_serializing_if = "Option::is_none")]
    pub email_link_primary: Option<bool>,
    #[serde(rename = "emailLinkSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub email_link_second_factor: Option<bool>,
    #[serde(rename = "certificatePrimary", default, skip_serializing_if = "Option::is_none")]
    pub certificate_primary: Option<bool>,
    #[serde(rename = "kerberosPrimary", default, skip_serializing_if = "Option::is_none")]
    pub kerberos_primary: Option<bool>,
    #[serde(rename = "walletPrimary", default, skip_serializing_if = "Option::is_none")]
    pub wallet_primary: Option<bool>,
    #[serde(rename = "walletSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub wallet_second_factor: Option<bool>,
    #[serde(rename = "federationPrimary", default, skip_serializing_if = "Option::is_none")]
    pub federation_primary: Option<bool>,
    #[serde(rename = "emailCodeTtlS", default, skip_serializing_if = "Option::is_none")]
    pub email_code_ttl_s: Option<String>,
    #[serde(rename = "emailCodeAttempts", default, skip_serializing_if = "Option::is_none")]
    pub email_code_attempts: Option<String>,
    #[serde(rename = "emailResendS", default, skip_serializing_if = "Option::is_none")]
    pub email_resend_s: Option<String>,
    #[serde(rename = "emailFailureLimit", default, skip_serializing_if = "Option::is_none")]
    pub email_failure_limit: Option<String>,
    #[serde(rename = "rememberedBrowserSkipsSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub remembered_browser_skips_second_factor: Option<String>,
    #[serde(rename = "rememberedBrowserDays", default, skip_serializing_if = "Option::is_none")]
    pub remembered_browser_days: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "policyMechanism", default, skip_serializing_if = "Option::is_none")]
    pub policy_mechanism: Option<Vec<String>>,
    #[serde(rename = "policySecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub policy_second_factor: Option<Vec<String>>,
    #[serde(rename = "policyPrecedence", default, skip_serializing_if = "Option::is_none")]
    pub policy_precedence: Option<i64>,
    #[serde(rename = "stsMailFactor", default, skip_serializing_if = "Option::is_none")]
    pub sts_mail_factor: Option<String>,
    #[serde(rename = "stsMailFactorFailures", default, skip_serializing_if = "Option::is_none")]
    pub sts_mail_factor_failures: Option<i64>,
}

impl AuthenticationPolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.authn");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "requireSecondFactor",
            attribute: Some("stsAuthnRequireSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requireSecondFactorForAdministrators",
            attribute: Some("stsAuthnRequireSecondFactorForAdministrators"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordPrimary",
            attribute: Some("stsAuthnPasswordPrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordSecondFactor",
            attribute: Some("stsAuthnPasswordSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passkeyPrimary",
            attribute: Some("stsAuthnPasskeyPrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "securityKeySecondFactor",
            attribute: Some("stsAuthnSecurityKeySecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "totpSecondFactor",
            attribute: Some("stsAuthnTotpSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "recoveryCodeSecondFactor",
            attribute: Some("stsAuthnRecoveryCodeSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailCodePrimary",
            attribute: Some("stsAuthnEmailCodePrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailCodeSecondFactor",
            attribute: Some("stsAuthnEmailCodeSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailLinkPrimary",
            attribute: Some("stsAuthnEmailLinkPrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailLinkSecondFactor",
            attribute: Some("stsAuthnEmailLinkSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificatePrimary",
            attribute: Some("stsAuthnCertificatePrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "kerberosPrimary",
            attribute: Some("stsAuthnKerberosPrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "walletPrimary",
            attribute: Some("stsAuthnWalletPrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "walletSecondFactor",
            attribute: Some("stsAuthnWalletSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationPrimary",
            attribute: Some("stsAuthnFederationPrimary"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailCodeTtlS",
            attribute: Some("stsAuthnEmailCodeTtlS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailCodeAttempts",
            attribute: Some("stsAuthnEmailCodeAttempts"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailResendS",
            attribute: Some("stsAuthnEmailResendS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailFailureLimit",
            attribute: Some("stsAuthnEmailFailureLimit"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rememberedBrowserSkipsSecondFactor",
            attribute: Some("stsAuthnRememberedBrowserSkipsSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rememberedBrowserDays",
            attribute: Some("stsAuthnRememberedBrowserDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policyMechanism",
            attribute: Some("stsAuthnPolicyMechanism"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policySecondFactor",
            attribute: Some("stsAuthnPolicySecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policyPrecedence",
            attribute: Some("stsAuthnPolicyPrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsMailFactor",
            attribute: Some("stsMailFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsMailFactorFailures",
            attribute: Some("stsMailFactorFailures"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Certificate enrollment by EST, ACME or SCEP.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateEnrollment {
    #[serde(rename = "allowedProfiles", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(rename = "certificateLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days: Option<String>,
    #[serde(rename = "allowedProfiles2", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles2: Option<Vec<String>>,
    #[serde(rename = "defaultProfile2", default, skip_serializing_if = "Option::is_none")]
    pub default_profile2: Option<String>,
    #[serde(rename = "certificateLifetimeDays2", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days2: Option<String>,
    #[serde(rename = "allowedProfiles3", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles3: Option<Vec<String>>,
    #[serde(rename = "defaultProfile3", default, skip_serializing_if = "Option::is_none")]
    pub default_profile3: Option<String>,
    #[serde(rename = "certificateLifetimeDays3", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days3: Option<String>,
    #[serde(rename = "basicAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub basic_authentication: Option<String>,
    #[serde(rename = "certificateAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub certificate_authentication: Option<String>,
    #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
    pub server_key_generation: Option<String>,
}

impl CertificateEnrollment {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "allowedProfiles",
            attribute: Some("acmeAllowedProfiles"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultProfile",
            attribute: Some("acmeDefaultProfile"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateLifetimeDays",
            attribute: Some("acmeCertificateLifetimeDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedProfiles2",
            attribute: Some("estAllowedProfiles"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultProfile2",
            attribute: Some("estDefaultProfile"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateLifetimeDays2",
            attribute: Some("estCertificateLifetimeDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedProfiles3",
            attribute: Some("scepAllowedProfiles"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultProfile3",
            attribute: Some("scepDefaultProfile"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateLifetimeDays3",
            attribute: Some("scepCertificateLifetimeDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "basicAuthentication",
            attribute: Some("estBasicAuthentication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateAuthentication",
            attribute: Some("estCertificateAuthentication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "serverKeyGeneration",
            attribute: Some("estServerKeyGeneration"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// An OpenID Connect claims provider.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimProvider {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl ClaimProvider {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("claimProvider");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "data",
            attribute: Some("stsClaimProviderData"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "secret",
            attribute: Some("stsClaimProviderSecret"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
    ];
}

/// Everything a person proves themselves with: the concept a User deliberately
/// is not.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    #[serde(rename = "passwordHash", default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(rename = "authenticatorApp", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkeys: Option<Vec<String>>,
    #[serde(rename = "recoveryCodes", default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<String>,
    #[serde(rename = "appPasswords", default, skip_serializing_if = "Option::is_none")]
    pub app_passwords: Option<String>,
    #[serde(rename = "passwordChanged", default, skip_serializing_if = "Option::is_none")]
    pub password_changed: Option<String>,
    #[serde(rename = "passwordMustChange", default, skip_serializing_if = "Option::is_none")]
    pub password_must_change: Option<bool>,
    #[serde(rename = "lockedSince", default, skip_serializing_if = "Option::is_none")]
    pub locked_since: Option<String>,
    #[serde(rename = "userCertificate", default, skip_serializing_if = "Option::is_none")]
    pub user_certificate: Option<Vec<String>>,
    #[serde(rename = "krb5KeyInfo", default, skip_serializing_if = "Option::is_none")]
    pub krb5_key_info: Option<String>,
    #[serde(rename = "hobaPublicKey", default, skip_serializing_if = "Option::is_none")]
    pub hoba_public_key: Option<Vec<String>>,
    #[serde(rename = "activationExpires", default, skip_serializing_if = "Option::is_none")]
    pub activation_expires: Option<String>,
    #[serde(rename = "passwordResetExpires", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_expires: Option<String>,
    #[serde(rename = "pwdHistory", default, skip_serializing_if = "Option::is_none")]
    pub pwd_history: Option<Vec<String>>,
    #[serde(rename = "activationToken", default, skip_serializing_if = "Option::is_none")]
    pub activation_token: Option<String>,
    #[serde(rename = "profilePhoto", default, skip_serializing_if = "Option::is_none")]
    pub profile_photo: Option<String>,
    #[serde(rename = "passwordResetToken", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_token: Option<String>,
    #[serde(rename = "krb5Keys", default, skip_serializing_if = "Option::is_none")]
    pub krb5_keys: Option<String>,
    #[serde(rename = "selfIssuedSubject", default, skip_serializing_if = "Option::is_none")]
    pub self_issued_subject: Option<Vec<String>>,
    #[serde(rename = "publishedDid", default, skip_serializing_if = "Option::is_none")]
    pub published_did: Option<Vec<String>>,
    #[serde(rename = "cibaUserCode", default, skip_serializing_if = "Option::is_none")]
    pub ciba_user_code: Option<String>,
    #[serde(rename = "androidAttestedCredential", default, skip_serializing_if = "Option::is_none")]
    pub android_attested_credential: Option<Vec<String>>,
    #[serde(rename = "webauthnUserHandle", default, skip_serializing_if = "Option::is_none")]
    pub webauthn_user_handle: Option<String>,
    #[serde(rename = "webauthnPqcUserHandle", default, skip_serializing_if = "Option::is_none")]
    pub webauthn_pqc_user_handle: Option<String>,
    #[serde(rename = "mailVerifyToken", default, skip_serializing_if = "Option::is_none")]
    pub mail_verify_token: Option<String>,
    #[serde(rename = "mailVerifyExpires", default, skip_serializing_if = "Option::is_none")]
    pub mail_verify_expires: Option<String>,
    #[serde(rename = "mailVerifyAddress", default, skip_serializing_if = "Option::is_none")]
    pub mail_verify_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonym: Option<Vec<String>>,
    #[serde(rename = "pseudonymVerifyToken", default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_verify_token: Option<String>,
    #[serde(rename = "pseudonymVerifyExpires", default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_verify_expires: Option<String>,
    #[serde(rename = "pseudonymVerifyAddress", default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_verify_address: Option<String>,
    #[serde(rename = "assertionIssuer", default, skip_serializing_if = "Option::is_none")]
    pub assertion_issuer: Option<Vec<String>>,
    #[serde(rename = "assertionKeyPair", default, skip_serializing_if = "Option::is_none")]
    pub assertion_key_pair: Option<Vec<String>>,
    #[serde(rename = "assertionPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub assertion_private_key: Option<Vec<String>>,
    #[serde(rename = "samlAssertionIssuer", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_issuer: Option<Vec<String>>,
    #[serde(rename = "samlAssertionKeyPair", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_key_pair: Option<Vec<String>>,
    #[serde(rename = "samlAssertionPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_private_key: Option<Vec<String>>,
    #[serde(rename = "enrolledCertificate", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_certificate: Option<Vec<String>>,
    #[serde(rename = "enrolledPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_private_key: Option<Vec<String>>,
    #[serde(rename = "acmeEabKey", default, skip_serializing_if = "Option::is_none")]
    pub acme_eab_key: Option<Vec<String>>,
    #[serde(rename = "scepChallenge", default, skip_serializing_if = "Option::is_none")]
    pub scep_challenge: Option<Vec<String>>,
    #[serde(rename = "certificateHostName", default, skip_serializing_if = "Option::is_none")]
    pub certificate_host_name: Option<Vec<String>>,
    #[serde(rename = "idaVerification", default, skip_serializing_if = "Option::is_none")]
    pub ida_verification: Option<String>,
    #[serde(rename = "claimSourceTokens", default, skip_serializing_if = "Option::is_none")]
    pub claim_source_tokens: Option<String>,
}

impl Credential {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("person");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "passwordHash",
            attribute: Some("userPassword"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authenticatorApp",
            attribute: Some("stsTotpCredential"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passkeys",
            attribute: Some("stsWebauthnCredential"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "recoveryCodes",
            attribute: Some("stsBackupCodes"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "appPasswords",
            attribute: Some("stsAppPassword"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordChanged",
            attribute: Some("pwdChangedTime"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordMustChange",
            attribute: Some("pwdReset"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lockedSince",
            attribute: Some("pwdAccountLockedTime"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userCertificate",
            attribute: Some("userCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "krb5KeyInfo",
            attribute: Some("stsKrb5KeyInfo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "hobaPublicKey",
            attribute: Some("hobaPublicKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "activationExpires",
            attribute: Some("stsActivationExpires"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordResetExpires",
            attribute: Some("stsPasswordResetExpires"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pwdHistory",
            attribute: Some("pwdHistory"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "activationToken",
            attribute: Some("stsActivationToken"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "profilePhoto",
            attribute: Some("stsProfilePhoto"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordResetToken",
            attribute: Some("stsPasswordResetToken"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "krb5Keys",
            attribute: Some("stsKrb5Keys"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "selfIssuedSubject",
            attribute: Some("stsSelfIssuedSubject"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "publishedDid",
            attribute: Some("stsPublishedDid"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "cibaUserCode",
            attribute: Some("stsCibaUserCode"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "androidAttestedCredential",
            attribute: Some("stsAndroidAttestedCredential"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "webauthnUserHandle",
            attribute: Some("stsWebauthnUserHandle"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "webauthnPqcUserHandle",
            attribute: Some("stsWebauthnPqcUserHandle"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mailVerifyToken",
            attribute: Some("stsMailVerifyToken"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mailVerifyExpires",
            attribute: Some("stsMailVerifyExpires"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mailVerifyAddress",
            attribute: Some("stsMailVerifyAddress"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pseudonym",
            attribute: Some("stsPseudonym"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pseudonymVerifyToken",
            attribute: Some("stsPseudonymVerifyToken"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pseudonymVerifyExpires",
            attribute: Some("stsPseudonymVerifyExpires"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pseudonymVerifyAddress",
            attribute: Some("stsPseudonymVerifyAddress"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionIssuer",
            attribute: Some("stsAssertionIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionKeyPair",
            attribute: Some("stsAssertionKeyPair"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionPrivateKey",
            attribute: Some("stsAssertionPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionIssuer",
            attribute: Some("stsSamlAssertionIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionKeyPair",
            attribute: Some("stsSamlAssertionKeyPair"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionPrivateKey",
            attribute: Some("stsSamlAssertionPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enrolledCertificate",
            attribute: Some("stsEnrolledCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enrolledPrivateKey",
            attribute: Some("stsEnrolledPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "acmeEabKey",
            attribute: Some("stsAcmeEabKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scepChallenge",
            attribute: Some("stsScepChallenge"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateHostName",
            attribute: Some("stsCertificateHostName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idaVerification",
            attribute: Some("stsIdaVerification"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimSourceTokens",
            attribute: Some("stsClaimSourceTokens"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
    ];
}

/// A device registered in a realm, and what is known about its state.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Vec<String>>,
    #[serde(rename = "keyThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<Vec<String>>,
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<Vec<String>>,
    #[serde(rename = "androidKey", default, skip_serializing_if = "Option::is_none")]
    pub android_key: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
    pub compliance_change: Option<String>,
    #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
    pub status_change: Option<String>,
    #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
    pub risk_change: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolment: Option<String>,
    #[serde(rename = "secretHash", default, skip_serializing_if = "Option::is_none")]
    pub secret_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

impl Device {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("device");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "identifier",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "owner",
            attribute: Some("owner"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "ownerKind",
            attribute: Some("stsDeviceOwnerKind"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "applications",
            attribute: Some("stsDeviceApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "compliance",
            attribute: Some("stsDeviceCompliance"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "status",
            attribute: Some("stsDeviceStatus"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "riskLevel",
            attribute: Some("stsDeviceRiskLevel"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "platform",
            attribute: Some("stsDevicePlatform"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastUsed",
            attribute: Some("stsDeviceLastUsed"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "key",
            attribute: Some("stsDeviceKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keyThumbprint",
            attribute: Some("stsDeviceKeyThumbprint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "credentialId",
            attribute: Some("stsDeviceCredentialId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "androidKey",
            attribute: Some("stsDeviceAndroidKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "attestation",
            attribute: Some("stsDeviceAttestation"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "complianceChange",
            attribute: Some("stsDeviceComplianceChange"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "statusChange",
            attribute: Some("stsDeviceStatusChange"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "riskChange",
            attribute: Some("stsDeviceRiskChange"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "browser",
            attribute: Some("stsDeviceBrowser"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "model",
            attribute: Some("stsDeviceModel"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "os",
            attribute: Some("stsDeviceOs"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enrolment",
            attribute: Some("stsDeviceEnrolment"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "secretHash",
            attribute: Some("stsDeviceSecretHash"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "session",
            attribute: Some("stsDeviceSession"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What the directory keeps about any entry.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    #[serde(rename = "entryUuid", default, skip_serializing_if = "Option::is_none")]
    pub entry_uuid: Option<String>,
    #[serde(rename = "createTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub create_timestamp: Option<String>,
    #[serde(rename = "modifyTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub modify_timestamp: Option<String>,
    #[serde(rename = "entryDN", default, skip_serializing_if = "Option::is_none")]
    pub entry_dn: Option<String>,
    #[serde(rename = "stsEntryUuidAlias", default, skip_serializing_if = "Option::is_none")]
    pub sts_entry_uuid_alias: Option<Vec<String>>,
    #[serde(rename = "memberOf", default, skip_serializing_if = "Option::is_none")]
    pub member_of: Option<Vec<String>>,
}

impl DirectoryEntry {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("operational");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "entryUuid",
            attribute: Some("entryUUID"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "createTimestamp",
            attribute: Some("createTimestamp"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "modifyTimestamp",
            attribute: Some("modifyTimestamp"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "entryDN",
            attribute: Some("entryDN"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsEntryUuidAlias",
            attribute: Some("stsEntryUuidAlias"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "memberOf",
            attribute: Some("memberOf"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// An agreement with one partner, in either direction and one protocol.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationship {
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(rename = "localEntityId", default, skip_serializing_if = "Option::is_none")]
    pub local_entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(rename = "authorizationUrl", default, skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(rename = "tokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "userinfoUrl", default, skip_serializing_if = "Option::is_none")]
    pub userinfo_url: Option<String>,
    #[serde(rename = "emailsUrl", default, skip_serializing_if = "Option::is_none")]
    pub emails_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(rename = "trustAnchor", default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor: Option<String>,
    #[serde(rename = "signingCertificate", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate: Option<String>,
    #[serde(rename = "responseMode", default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(rename = "allowedTenants", default, skip_serializing_if = "Option::is_none")]
    pub allowed_tenants: Option<Vec<String>>,
    #[serde(rename = "teamId", default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(rename = "keyId", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(rename = "clientSigningKey", default, skip_serializing_if = "Option::is_none")]
    pub client_signing_key: Option<String>,
    #[serde(rename = "authorizeParams", default, skip_serializing_if = "Option::is_none")]
    pub authorize_params: Option<Vec<String>>,
    #[serde(rename = "tokenAuth", default, skip_serializing_if = "Option::is_none")]
    pub token_auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(rename = "responseType", default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(rename = "idTokenSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(rename = "userinfoSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo: Option<String>,
    #[serde(rename = "refreshTokens", default, skip_serializing_if = "Option::is_none")]
    pub refresh_tokens: Option<String>,
    #[serde(rename = "refreshEverySeconds", default, skip_serializing_if = "Option::is_none")]
    pub refresh_every_seconds: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
    #[serde(rename = "registeredIssuer", default, skip_serializing_if = "Option::is_none")]
    pub registered_issuer: Option<String>,
    #[serde(rename = "requestObject", default, skip_serializing_if = "Option::is_none")]
    pub request_object: Option<String>,
    #[serde(rename = "requestObjectSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    #[serde(rename = "webFinger", default, skip_serializing_if = "Option::is_none")]
    pub web_finger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fapi: Option<String>,
    #[serde(rename = "initiateLogin", default, skip_serializing_if = "Option::is_none")]
    pub initiate_login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(rename = "signRequest", default, skip_serializing_if = "Option::is_none")]
    pub sign_request: Option<String>,
    #[serde(rename = "usernameSource", default, skip_serializing_if = "Option::is_none")]
    pub username_source: Option<String>,
    #[serde(rename = "subjectClaim", default, skip_serializing_if = "Option::is_none")]
    pub subject_claim: Option<String>,
    #[serde(rename = "attributeMap", default, skip_serializing_if = "Option::is_none")]
    pub attribute_map: Option<Vec<String>>,
    #[serde(rename = "autocreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub autocreate_users: Option<String>,
    #[serde(rename = "updateUserAttributes", default, skip_serializing_if = "Option::is_none")]
    pub update_user_attributes: Option<String>,
    #[serde(rename = "provisionGroups", default, skip_serializing_if = "Option::is_none")]
    pub provision_groups: Option<String>,
    #[serde(rename = "provisionCap", default, skip_serializing_if = "Option::is_none")]
    pub provision_cap: Option<String>,
    #[serde(rename = "provisionIdleMinutes", default, skip_serializing_if = "Option::is_none")]
    pub provision_idle_minutes: Option<String>,
    #[serde(rename = "subjectPolicy", default, skip_serializing_if = "Option::is_none")]
    pub subject_policy: Option<String>,
    #[serde(rename = "subjectGroup", default, skip_serializing_if = "Option::is_none")]
    pub subject_group: Option<Vec<String>>,
    #[serde(rename = "subjectDomain", default, skip_serializing_if = "Option::is_none")]
    pub subject_domain: Option<Vec<String>>,
    #[serde(rename = "homeRealmDomain", default, skip_serializing_if = "Option::is_none")]
    pub home_realm_domain: Option<Vec<String>>,
    #[serde(rename = "subjectPattern", default, skip_serializing_if = "Option::is_none")]
    pub subject_pattern: Option<String>,
    #[serde(rename = "mayAssertAdministrators", default, skip_serializing_if = "Option::is_none")]
    pub may_assert_administrators: Option<String>,
    #[serde(rename = "signalEmailMatch", default, skip_serializing_if = "Option::is_none")]
    pub signal_email_match: Option<String>,
    #[serde(rename = "signalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub signals_enabled: Option<String>,
    #[serde(rename = "signalsIssuer", default, skip_serializing_if = "Option::is_none")]
    pub signals_issuer: Option<String>,
    #[serde(rename = "signalsDelivery", default, skip_serializing_if = "Option::is_none")]
    pub signals_delivery: Option<String>,
    #[serde(rename = "signalsEvents", default, skip_serializing_if = "Option::is_none")]
    pub signals_events: Option<Vec<String>>,
    #[serde(rename = "signalsTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub signals_token_url: Option<String>,
    #[serde(rename = "signalsClientId", default, skip_serializing_if = "Option::is_none")]
    pub signals_client_id: Option<String>,
    #[serde(rename = "signalsClientSecret", default, skip_serializing_if = "Option::is_none")]
    pub signals_client_secret: Option<String>,
    #[serde(rename = "signalsScope", default, skip_serializing_if = "Option::is_none")]
    pub signals_scope: Option<String>,
    #[serde(rename = "signalsBearer", default, skip_serializing_if = "Option::is_none")]
    pub signals_bearer: Option<String>,
    #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
    #[serde(rename = "sloBinding", default, skip_serializing_if = "Option::is_none")]
    pub slo_binding: Option<String>,
    #[serde(rename = "endSessionUrl", default, skip_serializing_if = "Option::is_none")]
    pub end_session_url: Option<String>,
    #[serde(rename = "acceptSignout", default, skip_serializing_if = "Option::is_none")]
    pub accept_signout: Option<String>,
    #[serde(rename = "requireSignedLogout", default, skip_serializing_if = "Option::is_none")]
    pub require_signed_logout: Option<String>,
    #[serde(rename = "encryptionKeyType", default, skip_serializing_if = "Option::is_none")]
    pub encryption_key_type: Option<String>,
    #[serde(rename = "keyManagementAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub key_management_algorithm: Option<String>,
    #[serde(rename = "contentEncryptionAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub content_encryption_algorithm: Option<String>,
    #[serde(rename = "allowUnencrypted", default, skip_serializing_if = "Option::is_none")]
    pub allow_unencrypted: Option<String>,
    #[serde(rename = "encryptionKey", default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<Vec<String>>,
    #[serde(rename = "clientCertificate", default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    #[serde(rename = "allowUnsolicited", default, skip_serializing_if = "Option::is_none")]
    pub allow_unsolicited: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "authnMechanism", default, skip_serializing_if = "Option::is_none")]
    pub authn_mechanism: Option<String>,
    #[serde(rename = "authnRelationship", default, skip_serializing_if = "Option::is_none")]
    pub authn_relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<Vec<String>>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<String>,
    #[serde(rename = "lastUser", default, skip_serializing_if = "Option::is_none")]
    pub last_user: Option<String>,
    #[serde(rename = "applicationUse", default, skip_serializing_if = "Option::is_none")]
    pub application_use: Option<Vec<String>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "lastErrorAt", default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<String>,
}

impl FederationRelationship {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("federationRelationship");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "identifier",
            attribute: Some("fedId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "name",
            attribute: Some("fedName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "role",
            attribute: Some("fedRole"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "protocol",
            attribute: Some("fedProtocol"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "provider",
            attribute: Some("fedProvider"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "peer",
            attribute: Some("fedPeer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "localEntityId",
            attribute: Some("fedLocalEntityId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enabled",
            attribute: Some("fedEnabled"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientId",
            attribute: Some("fedClientId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientSecret",
            attribute: Some("fedClientSecret"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationUrl",
            attribute: Some("fedSsoUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tokenUrl",
            attribute: Some("fedTokenUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jwksUri",
            attribute: Some("fedJwksUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "cn",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userinfoUrl",
            attribute: Some("fedUserinfoUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "emailsUrl",
            attribute: Some("fedEmailsUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jwks",
            attribute: Some("fedJwks"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "trustAnchor",
            attribute: Some("fedTrustAnchor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signingCertificate",
            attribute: Some("fedSigningCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "responseMode",
            attribute: Some("fedResponseMode"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedTenants",
            attribute: Some("fedAllowedTenants"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "teamId",
            attribute: Some("fedTeamId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keyId",
            attribute: Some("fedKeyId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientSigningKey",
            attribute: Some("fedClientSigningKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizeParams",
            attribute: Some("fedAuthorizeParams"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tokenAuth",
            attribute: Some("fedTokenAuth"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scope",
            attribute: Some("fedScope"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "responseType",
            attribute: Some("fedResponseType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idTokenSignedResponseAlg",
            attribute: Some("fedIdTokenSignedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userinfoSignedResponseAlg",
            attribute: Some("fedUserinfoSignedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userinfo",
            attribute: Some("fedUserinfo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "refreshTokens",
            attribute: Some("fedRefreshTokens"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "refreshEverySeconds",
            attribute: Some("fedRefreshEverySeconds"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "register",
            attribute: Some("fedRegister"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registeredIssuer",
            attribute: Some("fedRegisteredIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requestObject",
            attribute: Some("fedRequestObject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requestObjectSigningAlg",
            attribute: Some("fedRequestObjectSigningAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "webFinger",
            attribute: Some("fedWebFinger"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "discovery",
            attribute: Some("fedDiscovery"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "fapi",
            attribute: Some("fedFapi"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "initiateLogin",
            attribute: Some("fedInitiateLogin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "binding",
            attribute: Some("fedBinding"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signRequest",
            attribute: Some("fedSignRequest"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "usernameSource",
            attribute: Some("fedUsernameSource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectClaim",
            attribute: Some("fedSubjectClaim"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "attributeMap",
            attribute: Some("fedAttributeMap"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "autocreateUsers",
            attribute: Some("fedAutocreateUsers"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "updateUserAttributes",
            attribute: Some("fedUpdateUserAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "provisionGroups",
            attribute: Some("fedProvisionGroups"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "provisionCap",
            attribute: Some("fedProvisionCap"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "provisionIdleMinutes",
            attribute: Some("fedProvisionIdleMinutes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectPolicy",
            attribute: Some("fedSubjectPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectGroup",
            attribute: Some("fedSubjectGroup"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectDomain",
            attribute: Some("fedSubjectDomain"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "homeRealmDomain",
            attribute: Some("fedHomeRealmDomain"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectPattern",
            attribute: Some("fedSubjectPattern"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mayAssertAdministrators",
            attribute: Some("fedMayAssertAdministrators"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalEmailMatch",
            attribute: Some("fedSignalEmailMatch"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsEnabled",
            attribute: Some("fedSignalsEnabled"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsIssuer",
            attribute: Some("fedSignalsIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsDelivery",
            attribute: Some("fedSignalsDelivery"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsEvents",
            attribute: Some("fedSignalsEvents"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsTokenUrl",
            attribute: Some("fedSignalsTokenUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsClientId",
            attribute: Some("fedSignalsClientId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsClientSecret",
            attribute: Some("fedSignalsClientSecret"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsScope",
            attribute: Some("fedSignalsScope"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signalsBearer",
            attribute: Some("fedSignalsBearer"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sloUrl",
            attribute: Some("fedSloUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sloBinding",
            attribute: Some("fedSloBinding"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "endSessionUrl",
            attribute: Some("fedEndSessionUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "acceptSignout",
            attribute: Some("fedAcceptSignout"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requireSignedLogout",
            attribute: Some("fedRequireSignedLogout"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "encryptionKeyType",
            attribute: Some("fedEncryptionKeyType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keyManagementAlgorithm",
            attribute: Some("fedKeyManagementAlgorithm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "contentEncryptionAlgorithm",
            attribute: Some("fedContentEncryptionAlgorithm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowUnencrypted",
            attribute: Some("fedAllowUnencrypted"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "encryptionKey",
            attribute: Some("fedEncryptionKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientCertificate",
            attribute: Some("fedClientCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowUnsolicited",
            attribute: Some("fedAllowUnsolicited"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "application",
            attribute: Some("fedApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authnMechanism",
            attribute: Some("fedAuthnMechanism"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authnRelationship",
            attribute: Some("fedAuthnRelationship"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "release",
            attribute: Some("fedRelease"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "firstSeen",
            attribute: Some("fedFirstSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSeen",
            attribute: Some("fedLastSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authentications",
            attribute: Some("fedAuthentications"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "users",
            attribute: Some("fedUsers"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastUser",
            attribute: Some("fedLastUser"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "applicationUse",
            attribute: Some("fedApplicationUse"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastError",
            attribute: Some("fedLastError"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastErrorAt",
            attribute: Some("fedLastErrorAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A GNAP client.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapClient {
    #[serde(rename = "claimsAccessToken", default, skip_serializing_if = "Option::is_none")]
    pub claims_access_token: Option<String>,
    #[serde(rename = "instanceId", default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "keyIdentity", default, skip_serializing_if = "Option::is_none")]
    pub key_identity: Option<String>,
    #[serde(rename = "keyReference", default, skip_serializing_if = "Option::is_none")]
    pub key_reference: Option<String>,
    #[serde(rename = "keyProof", default, skip_serializing_if = "Option::is_none")]
    pub key_proof: Option<String>,
    #[serde(rename = "mtlsTrust", default, skip_serializing_if = "Option::is_none")]
    pub mtls_trust: Option<String>,
    #[serde(rename = "symmetricKey", default, skip_serializing_if = "Option::is_none")]
    pub symmetric_key: Option<String>,
    #[serde(rename = "symmetricAlg", default, skip_serializing_if = "Option::is_none")]
    pub symmetric_alg: Option<String>,
    #[serde(rename = "classId", default, skip_serializing_if = "Option::is_none")]
    pub class_id: Option<String>,
    #[serde(rename = "displayUri", default, skip_serializing_if = "Option::is_none")]
    pub display_uri: Option<String>,
    #[serde(rename = "logoUri", default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(rename = "finishUri", default, skip_serializing_if = "Option::is_none")]
    pub finish_uri: Option<Vec<String>>,
    #[serde(rename = "interactionStartModes", default, skip_serializing_if = "Option::is_none")]
    pub interaction_start_modes: Option<Vec<String>>,
    #[serde(rename = "allowedAccess", default, skip_serializing_if = "Option::is_none")]
    pub allowed_access: Option<Vec<String>>,
    #[serde(rename = "bearerTokens", default, skip_serializing_if = "Option::is_none")]
    pub bearer_tokens: Option<String>,
    #[serde(rename = "skipInteraction", default, skip_serializing_if = "Option::is_none")]
    pub skip_interaction: Option<String>,
    #[serde(rename = "accessTokenFormat", default, skip_serializing_if = "Option::is_none")]
    pub access_token_format: Option<String>,
    #[serde(rename = "accessTokenLifetimeS", default, skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime_s: Option<String>,
    #[serde(rename = "resourceServerUri", default, skip_serializing_if = "Option::is_none")]
    pub resource_server_uri: Option<Vec<String>>,
    #[serde(rename = "ownerLookupUri", default, skip_serializing_if = "Option::is_none")]
    pub owner_lookup_uri: Option<String>,
    #[serde(rename = "jweKey", default, skip_serializing_if = "Option::is_none")]
    pub jwe_key: Option<String>,
    #[serde(rename = "macaroonKey", default, skip_serializing_if = "Option::is_none")]
    pub macaroon_key: Option<String>,
    #[serde(rename = "scopedSignals", default, skip_serializing_if = "Option::is_none")]
    pub scoped_signals: Option<String>,
}

impl GnapClient {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "claimsAccessToken",
            attribute: Some("gnapClaimsAccessToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "instanceId",
            attribute: Some("gnapInstanceId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "key",
            attribute: Some("gnapKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keyIdentity",
            attribute: Some("gnapKeyIdentity"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keyReference",
            attribute: Some("gnapKeyReference"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keyProof",
            attribute: Some("gnapKeyProof"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mtlsTrust",
            attribute: Some("gnapMtlsTrust"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "symmetricKey",
            attribute: Some("gnapSymmetricKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "symmetricAlg",
            attribute: Some("gnapSymmetricAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "classId",
            attribute: Some("gnapClassId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "displayUri",
            attribute: Some("gnapDisplayUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "logoUri",
            attribute: Some("gnapLogoUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "finishUri",
            attribute: Some("gnapFinishUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "interactionStartModes",
            attribute: Some("gnapInteractionStartModes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedAccess",
            attribute: Some("gnapAllowedAccess"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "bearerTokens",
            attribute: Some("gnapBearerTokens"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "skipInteraction",
            attribute: Some("gnapSkipInteraction"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "accessTokenFormat",
            attribute: Some("gnapAccessTokenFormat"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "accessTokenLifetimeS",
            attribute: Some("gnapAccessTokenLifetimeS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "resourceServerUri",
            attribute: Some("gnapResourceServerUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "ownerLookupUri",
            attribute: Some("gnapOwnerLookupUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jweKey",
            attribute: Some("gnapJweKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "macaroonKey",
            attribute: Some("gnapMacaroonKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scopedSignals",
            attribute: Some("gnapScopedSignals"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A set of people, and the policies that apply to its members. A group grants
/// nothing by being a group.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "uniqueMember", default, skip_serializing_if = "Option::is_none")]
    pub unique_member: Option<Vec<String>>,
    #[serde(rename = "memberUid", default, skip_serializing_if = "Option::is_none")]
    pub member_uid: Option<Vec<String>>,
    #[serde(rename = "stsPasskeyPolicy", default, skip_serializing_if = "Option::is_none")]
    pub sts_passkey_policy: Option<String>,
    #[serde(rename = "stsLocalePolicy", default, skip_serializing_if = "Option::is_none")]
    pub sts_locale_policy: Option<String>,
    #[serde(rename = "stsPasswordPolicy", default, skip_serializing_if = "Option::is_none")]
    pub sts_password_policy: Option<String>,
    #[serde(rename = "stsAuthnPolicy", default, skip_serializing_if = "Option::is_none")]
    pub sts_authn_policy: Option<String>,
    #[serde(rename = "stsPostLoginPolicy", default, skip_serializing_if = "Option::is_none")]
    pub sts_post_login_policy: Option<String>,
    #[serde(rename = "stsAttributePolicy", default, skip_serializing_if = "Option::is_none")]
    pub sts_attribute_policy: Option<String>,
    #[serde(rename = "federationRelationship", default, skip_serializing_if = "Option::is_none")]
    pub federation_relationship: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl Group {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("group");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "name",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "members",
            attribute: Some("member"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "uniqueMember",
            attribute: Some("uniqueMember"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "memberUid",
            attribute: Some("memberUid"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPasskeyPolicy",
            attribute: Some("stsPasskeyPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsLocalePolicy",
            attribute: Some("stsLocalePolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPasswordPolicy",
            attribute: Some("stsPasswordPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsAuthnPolicy",
            attribute: Some("stsAuthnPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPostLoginPolicy",
            attribute: Some("stsPostLoginPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsAttributePolicy",
            attribute: Some("stsAttributePolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationRelationship",
            attribute: Some("federationRelationship"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "email",
            attribute: Some("mail"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "displayName",
            attribute: Some("displayName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A token this service issued, as its register remembers it. The signed value
/// is not kept.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedToken {
    pub id: String,
    pub kind: String,
    pub subject: String,
    pub issuer: String,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub expires: i64,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: i64,
    pub revocable: bool,
    #[serde(rename = "dpopThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub dpop_thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl IssuedToken {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Record("common/admin_stats.js recordJwt()");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "id",
            attribute: None,
            on: None,
            key: Some("jti"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "kind",
            attribute: None,
            on: None,
            key: Some("kind"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subject",
            attribute: None,
            on: None,
            key: Some("sub"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "issuer",
            attribute: None,
            on: None,
            key: Some("iss"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientId",
            attribute: None,
            on: None,
            key: Some("client_id"),
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "audience",
            attribute: None,
            on: None,
            key: Some("audience"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scope",
            attribute: None,
            on: None,
            key: Some("scope"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "expires",
            attribute: None,
            on: None,
            key: Some("exp"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sessionId",
            attribute: None,
            on: None,
            key: Some("sessionId"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "grantId",
            attribute: None,
            on: None,
            key: Some("grantId"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "revoked",
            attribute: None,
            on: None,
            key: Some("revoked"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "username",
            attribute: None,
            on: None,
            key: Some("username"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "issuedAt",
            attribute: None,
            on: None,
            key: Some("issuedAt"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "revocable",
            attribute: None,
            on: None,
            key: Some("revocable"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "dpopThumbprint",
            attribute: None,
            on: None,
            key: Some("jkt"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "state",
            attribute: None,
            on: None,
            key: Some("state"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A Kerberos service principal.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosService {
    #[serde(rename = "servicePrincipalName", default, skip_serializing_if = "Option::is_none")]
    pub service_principal_name: Option<Vec<String>>,
    #[serde(rename = "claimsPac", default, skip_serializing_if = "Option::is_none")]
    pub claims_pac: Option<String>,
    #[serde(rename = "trustedForDelegation", default, skip_serializing_if = "Option::is_none")]
    pub trusted_for_delegation: Option<String>,
    #[serde(rename = "s4uSelfRealm", default, skip_serializing_if = "Option::is_none")]
    pub s4u_self_realm: Option<Vec<String>>,
    #[serde(rename = "foreignTgtDelegation", default, skip_serializing_if = "Option::is_none")]
    pub foreign_tgt_delegation: Option<String>,
    #[serde(rename = "serviceKeys", default, skip_serializing_if = "Option::is_none")]
    pub service_keys: Option<String>,
    #[serde(rename = "serviceKeyInfo", default, skip_serializing_if = "Option::is_none")]
    pub service_key_info: Option<String>,
}

impl KerberosService {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "servicePrincipalName",
            attribute: Some("krb5ServicePrincipalName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsPac",
            attribute: Some("krb5ClaimsPac"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "trustedForDelegation",
            attribute: Some("krb5TrustedForDelegation"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "s4uSelfRealm",
            attribute: Some("krb5S4uSelfRealm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "foreignTgtDelegation",
            attribute: Some("krb5ForeignTgtDelegation"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "serviceKeys",
            attribute: Some("krb5ServiceKeys"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "serviceKeyInfo",
            attribute: Some("krb5ServiceKeyInfo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A Kerberos trust with another realm.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosTrust {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "trustPartner", default, skip_serializing_if = "Option::is_none")]
    pub trust_partner: Option<String>,
    #[serde(rename = "flatName", default, skip_serializing_if = "Option::is_none")]
    pub flat_name: Option<String>,
    #[serde(rename = "securityIdentifier", default, skip_serializing_if = "Option::is_none")]
    pub security_identifier: Option<String>,
    #[serde(rename = "trustDirection", default, skip_serializing_if = "Option::is_none")]
    pub trust_direction: Option<i64>,
    #[serde(rename = "trustAttributes", default, skip_serializing_if = "Option::is_none")]
    pub trust_attributes: Option<i64>,
    #[serde(rename = "trustType", default, skip_serializing_if = "Option::is_none")]
    pub trust_type: Option<i64>,
}

impl KerberosTrust {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("kerberosTrust");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "data",
            attribute: Some("stsKrb5TrustData"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keys",
            attribute: Some("stsKrb5TrustKeys"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "trustPartner",
            attribute: Some("trustPartner"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "flatName",
            attribute: Some("flatName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "securityIdentifier",
            attribute: Some("securityIdentifier"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "trustDirection",
            attribute: Some("trustDirection"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "trustAttributes",
            attribute: Some("trustAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "trustType",
            attribute: Some("trustType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Which languages a realm offers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(rename = "populatePreferredLanguage", default, skip_serializing_if = "Option::is_none")]
    pub populate_preferred_language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "stsPreferredLanguagePopulated", default, skip_serializing_if = "Option::is_none")]
    pub sts_preferred_language_populated: Option<String>,
}

impl LocalePolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.locale");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "default",
            attribute: Some("stsLocaleDefault"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "populatePreferredLanguage",
            attribute: Some("stsLocalePopulatePreferredLanguage"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "precedence",
            attribute: Some("stsLocalePrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPreferredLanguagePopulated",
            attribute: Some("stsPreferredLanguagePopulated"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What an OAuth 2.0 client or OpenID Connect relying party is registered with.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClient {
    #[serde(rename = "clientIds", default, skip_serializing_if = "Option::is_none")]
    pub client_ids: Option<Vec<String>>,
    #[serde(rename = "clientSecrets", default, skip_serializing_if = "Option::is_none")]
    pub client_secrets: Option<Vec<String>>,
    #[serde(rename = "redirectUris", default, skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(rename = "postLogoutRedirectUris", default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(rename = "grantTypes", default, skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    #[serde(rename = "responseTypes", default, skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    #[serde(rename = "tokenEndpointAuthMethods", default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods: Option<Vec<String>>,
    #[serde(rename = "idTokenSigningAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub id_token_signing_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    #[serde(rename = "claimsRedirectUri", default, skip_serializing_if = "Option::is_none")]
    pub claims_redirect_uri: Option<Vec<String>>,
    #[serde(rename = "frontchannelLogoutUri", default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(rename = "frontchannelLogoutSessionRequired", default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<String>,
    #[serde(rename = "backchannelLogoutUri", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(rename = "backchannelLogoutSessionRequired", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<String>,
    #[serde(rename = "allowedTokenResponseTypes", default, skip_serializing_if = "Option::is_none")]
    pub allowed_token_response_types: Option<Vec<String>>,
    #[serde(rename = "grantTypeObserved", default, skip_serializing_if = "Option::is_none")]
    pub grant_type_observed: Option<Vec<String>>,
    #[serde(rename = "responseTypeObserved", default, skip_serializing_if = "Option::is_none")]
    pub response_type_observed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<String>>,
    #[serde(rename = "allowedScope", default, skip_serializing_if = "Option::is_none")]
    pub allowed_scope: Option<Vec<String>>,
    #[serde(rename = "permissionBaseUri", default, skip_serializing_if = "Option::is_none")]
    pub permission_base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<Vec<String>>,
    #[serde(rename = "roleGatedPermission", default, skip_serializing_if = "Option::is_none")]
    pub role_gated_permission: Option<Vec<String>>,
    #[serde(rename = "resourceMetadata", default, skip_serializing_if = "Option::is_none")]
    pub resource_metadata: Option<String>,
    #[serde(rename = "resourceMetadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub resource_metadata_url: Option<String>,
    #[serde(rename = "delegatedPermission", default, skip_serializing_if = "Option::is_none")]
    pub delegated_permission: Option<Vec<String>>,
    #[serde(rename = "globalConsent", default, skip_serializing_if = "Option::is_none")]
    pub global_consent: Option<Vec<String>>,
    #[serde(rename = "globalConsentWithdrawn", default, skip_serializing_if = "Option::is_none")]
    pub global_consent_withdrawn: Option<Vec<String>>,
    #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
    pub native_sso: Option<String>,
    #[serde(rename = "nativeSsoGroup", default, skip_serializing_if = "Option::is_none")]
    pub native_sso_group: Option<String>,
    #[serde(rename = "backchannelTokenDeliveryMode", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_token_delivery_mode: Option<String>,
    #[serde(rename = "backchannelClientNotificationEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_client_notification_endpoint: Option<String>,
    #[serde(rename = "commandEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub command_endpoint: Option<String>,
    #[serde(rename = "backchannelAuthenticationRequestSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_authentication_request_signing_alg: Option<String>,
    #[serde(rename = "backchannelUserCodeParameter", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_user_code_parameter: Option<String>,
    #[serde(rename = "subjectType", default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(rename = "sectorIdentifierUri", default, skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,
    #[serde(rename = "didClaimWithPairwise", default, skip_serializing_if = "Option::is_none")]
    pub did_claim_with_pairwise: Option<String>,
    #[serde(rename = "tokenEndpointAuthSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(rename = "introspectionSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub introspection_signed_response_alg: Option<String>,
    #[serde(rename = "introspectionEncryptedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub introspection_encrypted_response_alg: Option<String>,
    #[serde(rename = "introspectionEncryptedResponseEnc", default, skip_serializing_if = "Option::is_none")]
    pub introspection_encrypted_response_enc: Option<String>,
    #[serde(rename = "requestUri", default, skip_serializing_if = "Option::is_none")]
    pub request_uri: Option<Vec<String>>,
    #[serde(rename = "requestObjectSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    #[serde(rename = "requestObjectEncryptionAlg", default, skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,
    #[serde(rename = "requestObjectEncryptionEnc", default, skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,
    #[serde(rename = "requireSignedRequestObject", default, skip_serializing_if = "Option::is_none")]
    pub require_signed_request_object: Option<String>,
    #[serde(rename = "requirePushedAuthorizationRequests", default, skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<String>,
    #[serde(rename = "httpSignedRequests", default, skip_serializing_if = "Option::is_none")]
    pub http_signed_requests: Option<String>,
    #[serde(rename = "authorizationDetailsType", default, skip_serializing_if = "Option::is_none")]
    pub authorization_details_type: Option<Vec<String>>,
    #[serde(rename = "authorizationDetailsTypes", default, skip_serializing_if = "Option::is_none")]
    pub authorization_details_types: Option<Vec<String>>,
    #[serde(rename = "stepUpAcrValues", default, skip_serializing_if = "Option::is_none")]
    pub step_up_acr_values: Option<String>,
    #[serde(rename = "stepUpMaxAge", default, skip_serializing_if = "Option::is_none")]
    pub step_up_max_age: Option<String>,
    #[serde(rename = "idTokenEncryptedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(rename = "idTokenEncryptedResponseEnc", default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(rename = "userinfoSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(rename = "userinfoEncryptedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(rename = "userinfoEncryptedResponseEnc", default, skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(rename = "authorizationSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub authorization_signed_response_alg: Option<String>,
    #[serde(rename = "authorizationEncryptedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(rename = "authorizationEncryptedResponseEnc", default, skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(rename = "defaultAcrValues", default, skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<String>,
    #[serde(rename = "defaultMaxAge", default, skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<String>,
    #[serde(rename = "assertionIssuer", default, skip_serializing_if = "Option::is_none")]
    pub assertion_issuer: Option<Vec<String>>,
    #[serde(rename = "assertionJwks", default, skip_serializing_if = "Option::is_none")]
    pub assertion_jwks: Option<String>,
    #[serde(rename = "assertionCertificate", default, skip_serializing_if = "Option::is_none")]
    pub assertion_certificate: Option<String>,
    #[serde(rename = "assertionCertificateChain", default, skip_serializing_if = "Option::is_none")]
    pub assertion_certificate_chain: Option<String>,
    #[serde(rename = "assertionPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub assertion_private_key: Option<String>,
    #[serde(rename = "assertionKid", default, skip_serializing_if = "Option::is_none")]
    pub assertion_kid: Option<String>,
    #[serde(rename = "assertionExpiresAt", default, skip_serializing_if = "Option::is_none")]
    pub assertion_expires_at: Option<String>,
    #[serde(rename = "assertionKeySource", default, skip_serializing_if = "Option::is_none")]
    pub assertion_key_source: Option<String>,
    #[serde(rename = "samlAssertionIssuer", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_issuer: Option<Vec<String>>,
    #[serde(rename = "samlAssertionSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_signing_certificate: Option<String>,
    #[serde(rename = "samlAssertionCertificate", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_certificate: Option<String>,
    #[serde(rename = "samlAssertionCertificateChain", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_certificate_chain: Option<String>,
    #[serde(rename = "samlAssertionPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_private_key: Option<String>,
    #[serde(rename = "samlAssertionThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_thumbprint: Option<String>,
    #[serde(rename = "samlAssertionExpiresAt", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_expires_at: Option<String>,
    #[serde(rename = "samlAssertionKeySource", default, skip_serializing_if = "Option::is_none")]
    pub saml_assertion_key_source: Option<String>,
    #[serde(rename = "softwareStatementIssuer", default, skip_serializing_if = "Option::is_none")]
    pub software_statement_issuer: Option<Vec<String>>,
    #[serde(rename = "issuedSoftwareStatement", default, skip_serializing_if = "Option::is_none")]
    pub issued_software_statement: Option<String>,
    #[serde(rename = "tlsClientAuthSubjectDn", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(rename = "tlsClientAuthSanDns", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_dns: Option<String>,
    #[serde(rename = "tlsClientAuthSanUri", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_uri: Option<String>,
    #[serde(rename = "tlsClientAuthSanIp", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_ip: Option<String>,
    #[serde(rename = "tlsClientAuthSanEmail", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_email: Option<String>,
    #[serde(rename = "tlsClientCertificateBoundAccessTokens", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<String>,
    #[serde(rename = "tlsClientCertificateThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidential: Option<String>,
    #[serde(rename = "accessTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub access_token_ttl_s: Option<String>,
    #[serde(rename = "idTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub id_token_ttl_s: Option<String>,
    #[serde(rename = "refreshTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_ttl_s: Option<String>,
    #[serde(rename = "refreshIdleSeconds", default, skip_serializing_if = "Option::is_none")]
    pub refresh_idle_seconds: Option<String>,
    #[serde(rename = "maxAuthAgeS", default, skip_serializing_if = "Option::is_none")]
    pub max_auth_age_s: Option<String>,
    #[serde(rename = "claimsAccessToken", default, skip_serializing_if = "Option::is_none")]
    pub claims_access_token: Option<String>,
    #[serde(rename = "claimsIdToken", default, skip_serializing_if = "Option::is_none")]
    pub claims_id_token: Option<String>,
    #[serde(rename = "claimsUserinfo", default, skip_serializing_if = "Option::is_none")]
    pub claims_userinfo: Option<String>,
    #[serde(rename = "claimAttributesAccessToken", default, skip_serializing_if = "Option::is_none")]
    pub claim_attributes_access_token: Option<String>,
    #[serde(rename = "claimAttributesIdToken", default, skip_serializing_if = "Option::is_none")]
    pub claim_attributes_id_token: Option<String>,
    #[serde(rename = "claimAttributesUserinfo", default, skip_serializing_if = "Option::is_none")]
    pub claim_attributes_userinfo: Option<String>,
    #[serde(rename = "claimsCombineAccessToken", default, skip_serializing_if = "Option::is_none")]
    pub claims_combine_access_token: Option<String>,
    #[serde(rename = "claimsCombineIdToken", default, skip_serializing_if = "Option::is_none")]
    pub claims_combine_id_token: Option<String>,
    #[serde(rename = "claimsCombineUserinfo", default, skip_serializing_if = "Option::is_none")]
    pub claims_combine_userinfo: Option<String>,
    #[serde(rename = "accessTokenClaim", default, skip_serializing_if = "Option::is_none")]
    pub access_token_claim: Option<Vec<String>>,
    #[serde(rename = "permissionClaims", default, skip_serializing_if = "Option::is_none")]
    pub permission_claims: Option<String>,
    #[serde(rename = "accessTokenClaimsCombine", default, skip_serializing_if = "Option::is_none")]
    pub access_token_claims_combine: Option<String>,
    #[serde(rename = "revokeRefreshOnLogout", default, skip_serializing_if = "Option::is_none")]
    pub revoke_refresh_on_logout: Option<String>,
    #[serde(rename = "thirdPartyInitiatedLogin", default, skip_serializing_if = "Option::is_none")]
    pub third_party_initiated_login: Option<String>,
    #[serde(rename = "spInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub sp_initiated_sso: Option<String>,
    #[serde(rename = "initiateLoginUri", default, skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,
    #[serde(rename = "logoUri", default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(rename = "policyUri", default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(rename = "tosUri", default, skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(rename = "tokenExchangeRefreshToken", default, skip_serializing_if = "Option::is_none")]
    pub token_exchange_refresh_token: Option<String>,
}

impl OAuthClient {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "clientIds",
            attribute: Some("oauthClientId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientSecrets",
            attribute: Some("oauthClientSecret"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "redirectUris",
            attribute: Some("oauthRedirectUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "postLogoutRedirectUris",
            attribute: Some("oauthPostLogoutRedirectUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "grantTypes",
            attribute: Some("oauthGrantType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "responseTypes",
            attribute: Some("oauthResponseType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tokenEndpointAuthMethods",
            attribute: Some("oauthTokenEndpointAuthMethod"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idTokenSigningAlgorithm",
            attribute: Some("oauthIdTokenSignedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "audience",
            attribute: Some("oauthAudience"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsRedirectUri",
            attribute: Some("oauthClaimsRedirectUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "frontchannelLogoutUri",
            attribute: Some("oauthFrontchannelLogoutUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "frontchannelLogoutSessionRequired",
            attribute: Some("oauthFrontchannelLogoutSessionRequired"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backchannelLogoutUri",
            attribute: Some("oauthBackchannelLogoutUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backchannelLogoutSessionRequired",
            attribute: Some("oauthBackchannelLogoutSessionRequired"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedTokenResponseTypes",
            attribute: Some("oauthAllowedTokenResponseTypes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "grantTypeObserved",
            attribute: Some("oauthGrantTypeObserved"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "responseTypeObserved",
            attribute: Some("oauthResponseTypeObserved"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scope",
            attribute: Some("oauthScope"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedScope",
            attribute: Some("oauthAllowedScope"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "permissionBaseUri",
            attribute: Some("oauthPermissionBaseUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "permission",
            attribute: Some("oauthPermission"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "roleGatedPermission",
            attribute: Some("oauthRoleGatedPermission"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "resourceMetadata",
            attribute: Some("oauthResourceMetadata"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "resourceMetadataUrl",
            attribute: Some("oauthResourceMetadataUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "delegatedPermission",
            attribute: Some("oauthDelegatedPermission"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "globalConsent",
            attribute: Some("oauthGlobalConsent"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "globalConsentWithdrawn",
            attribute: Some("oauthGlobalConsentWithdrawn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "nativeSso",
            attribute: Some("oauthNativeSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "nativeSsoGroup",
            attribute: Some("oauthNativeSsoGroup"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backchannelTokenDeliveryMode",
            attribute: Some("oauthBackchannelTokenDeliveryMode"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backchannelClientNotificationEndpoint",
            attribute: Some("oauthBackchannelClientNotificationEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "commandEndpoint",
            attribute: Some("oauthCommandEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backchannelAuthenticationRequestSigningAlg",
            attribute: Some("oauthBackchannelAuthenticationRequestSigningAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backchannelUserCodeParameter",
            attribute: Some("oauthBackchannelUserCodeParameter"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectType",
            attribute: Some("oauthSubjectType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sectorIdentifierUri",
            attribute: Some("oauthSectorIdentifierUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "didClaimWithPairwise",
            attribute: Some("oauthDidClaimWithPairwise"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tokenEndpointAuthSigningAlg",
            attribute: Some("oauthTokenEndpointAuthSigningAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jwks",
            attribute: Some("oauthJwks"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jwksUri",
            attribute: Some("oauthJwksUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "introspectionSignedResponseAlg",
            attribute: Some("oauthIntrospectionSignedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "introspectionEncryptedResponseAlg",
            attribute: Some("oauthIntrospectionEncryptedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "introspectionEncryptedResponseEnc",
            attribute: Some("oauthIntrospectionEncryptedResponseEnc"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requestUri",
            attribute: Some("oauthRequestUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requestObjectSigningAlg",
            attribute: Some("oauthRequestObjectSigningAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requestObjectEncryptionAlg",
            attribute: Some("oauthRequestObjectEncryptionAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requestObjectEncryptionEnc",
            attribute: Some("oauthRequestObjectEncryptionEnc"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requireSignedRequestObject",
            attribute: Some("oauthRequireSignedRequestObject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requirePushedAuthorizationRequests",
            attribute: Some("oauthRequirePushedAuthorizationRequests"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "httpSignedRequests",
            attribute: Some("oauthHttpSignedRequests"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationDetailsType",
            attribute: Some("oauthAuthorizationDetailsType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationDetailsTypes",
            attribute: Some("oauthAuthorizationDetailsTypes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stepUpAcrValues",
            attribute: Some("oauthStepUpAcrValues"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stepUpMaxAge",
            attribute: Some("oauthStepUpMaxAge"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idTokenEncryptedResponseAlg",
            attribute: Some("oauthIdTokenEncryptedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idTokenEncryptedResponseEnc",
            attribute: Some("oauthIdTokenEncryptedResponseEnc"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userinfoSignedResponseAlg",
            attribute: Some("oauthUserinfoSignedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userinfoEncryptedResponseAlg",
            attribute: Some("oauthUserinfoEncryptedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userinfoEncryptedResponseEnc",
            attribute: Some("oauthUserinfoEncryptedResponseEnc"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationSignedResponseAlg",
            attribute: Some("oauthAuthorizationSignedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationEncryptedResponseAlg",
            attribute: Some("oauthAuthorizationEncryptedResponseAlg"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authorizationEncryptedResponseEnc",
            attribute: Some("oauthAuthorizationEncryptedResponseEnc"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultAcrValues",
            attribute: Some("oauthDefaultAcrValues"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultMaxAge",
            attribute: Some("oauthDefaultMaxAge"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionIssuer",
            attribute: Some("oauthAssertionIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionJwks",
            attribute: Some("oauthAssertionJwks"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionCertificate",
            attribute: Some("oauthAssertionCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionCertificateChain",
            attribute: Some("oauthAssertionCertificateChain"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionPrivateKey",
            attribute: Some("oauthAssertionPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionKid",
            attribute: Some("oauthAssertionKid"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionExpiresAt",
            attribute: Some("oauthAssertionExpiresAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionKeySource",
            attribute: Some("oauthAssertionKeySource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionIssuer",
            attribute: Some("oauthSamlAssertionIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionSigningCertificate",
            attribute: Some("oauthSamlAssertionSigningCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionCertificate",
            attribute: Some("oauthSamlAssertionCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionCertificateChain",
            attribute: Some("oauthSamlAssertionCertificateChain"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionPrivateKey",
            attribute: Some("oauthSamlAssertionPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionThumbprint",
            attribute: Some("oauthSamlAssertionThumbprint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionExpiresAt",
            attribute: Some("oauthSamlAssertionExpiresAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "samlAssertionKeySource",
            attribute: Some("oauthSamlAssertionKeySource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "softwareStatementIssuer",
            attribute: Some("oauthSoftwareStatementIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "issuedSoftwareStatement",
            attribute: Some("oauthIssuedSoftwareStatement"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientAuthSubjectDn",
            attribute: Some("oauthTlsClientAuthSubjectDn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientAuthSanDns",
            attribute: Some("oauthTlsClientAuthSanDns"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientAuthSanUri",
            attribute: Some("oauthTlsClientAuthSanUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientAuthSanIp",
            attribute: Some("oauthTlsClientAuthSanIp"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientAuthSanEmail",
            attribute: Some("oauthTlsClientAuthSanEmail"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientCertificateBoundAccessTokens",
            attribute: Some("oauthTlsClientCertificateBoundAccessTokens"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tlsClientCertificateThumbprint",
            attribute: Some("oauthTlsClientCertificateThumbprint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "confidential",
            attribute: Some("oauthConfidential"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "accessTokenTtlS",
            attribute: Some("oauthAccessTokenTtlS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idTokenTtlS",
            attribute: Some("oauthIdTokenTtlS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "refreshTokenTtlS",
            attribute: Some("oauthRefreshTokenTtlS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "refreshIdleSeconds",
            attribute: Some("oauthRefreshIdleSeconds"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "maxAuthAgeS",
            attribute: Some("oauthMaxAuthAgeS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsAccessToken",
            attribute: Some("oauthClaimsAccessToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsIdToken",
            attribute: Some("oauthClaimsIdToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsUserinfo",
            attribute: Some("oauthClaimsUserinfo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimAttributesAccessToken",
            attribute: Some("oauthClaimAttributesAccessToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimAttributesIdToken",
            attribute: Some("oauthClaimAttributesIdToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimAttributesUserinfo",
            attribute: Some("oauthClaimAttributesUserinfo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsCombineAccessToken",
            attribute: Some("oauthClaimsCombineAccessToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsCombineIdToken",
            attribute: Some("oauthClaimsCombineIdToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "claimsCombineUserinfo",
            attribute: Some("oauthClaimsCombineUserinfo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "accessTokenClaim",
            attribute: Some("oauthAccessTokenClaim"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "permissionClaims",
            attribute: Some("oauthPermissionClaims"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "accessTokenClaimsCombine",
            attribute: Some("oauthAccessTokenClaimsCombine"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "revokeRefreshOnLogout",
            attribute: Some("oauthRevokeRefreshOnLogout"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "thirdPartyInitiatedLogin",
            attribute: Some("oauthThirdPartyInitiatedLogin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spInitiatedSso",
            attribute: Some("oauthSpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "initiateLoginUri",
            attribute: Some("oauthInitiateLoginUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "logoUri",
            attribute: Some("oauthLogoUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policyUri",
            attribute: Some("oauthPolicyUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tosUri",
            attribute: Some("oauthTosUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "tokenExchangeRefreshToken",
            attribute: Some("oauthTokenExchangeRefreshToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// An OpenID Federation entity this realm holds.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenIdFederationEntity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Vec<String>>,
}

impl OpenIdFederationEntity {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("oidfed");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "kind",
            attribute: Some("stsOidfedKind"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "entityId",
            attribute: Some("stsOidfedEntityId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "data",
            attribute: Some("stsOidfedData"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "keys",
            attribute: Some("stsOidfedKeys"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "event",
            attribute: Some("stsOidfedEvent"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What a passkey must be.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyPolicy {
    #[serde(rename = "allowUsernameless", default, skip_serializing_if = "Option::is_none")]
    pub allow_usernameless: Option<String>,
    #[serde(rename = "requireUsernameless", default, skip_serializing_if = "Option::is_none")]
    pub require_usernameless: Option<String>,
    #[serde(rename = "securityKeyResidentKey", default, skip_serializing_if = "Option::is_none")]
    pub security_key_resident_key: Option<String>,
    #[serde(rename = "backupEligibility", default, skip_serializing_if = "Option::is_none")]
    pub backup_eligibility: Option<String>,
    #[serde(rename = "enforcePinLength", default, skip_serializing_if = "Option::is_none")]
    pub enforce_pin_length: Option<String>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<String>,
    #[serde(rename = "pinLengthOnlyIfSupported", default, skip_serializing_if = "Option::is_none")]
    pub pin_length_only_if_supported: Option<String>,
    #[serde(rename = "enforceAttestationAtSignIn", default, skip_serializing_if = "Option::is_none")]
    pub enforce_attestation_at_sign_in: Option<String>,
    #[serde(rename = "postQuantumRequired", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_required: Option<String>,
    #[serde(rename = "postQuantumAllowCredentials", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_allow_credentials: Option<String>,
    #[serde(rename = "registrationAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub registration_algorithms: Option<String>,
    #[serde(rename = "registrationMode", default, skip_serializing_if = "Option::is_none")]
    pub registration_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lanes: Option<String>,
    #[serde(rename = "clientRules", default, skip_serializing_if = "Option::is_none")]
    pub client_rules: Option<String>,
    #[serde(rename = "hintsPasskey", default, skip_serializing_if = "Option::is_none")]
    pub hints_passkey: Option<String>,
    #[serde(rename = "hintsSecurityKey", default, skip_serializing_if = "Option::is_none")]
    pub hints_security_key: Option<String>,
    #[serde(rename = "hintsSignIn", default, skip_serializing_if = "Option::is_none")]
    pub hints_sign_in: Option<String>,
    #[serde(rename = "enterpriseSerialAttribute", default, skip_serializing_if = "Option::is_none")]
    pub enterprise_serial_attribute: Option<String>,
    #[serde(rename = "userDisplayName", default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    #[serde(rename = "rpNameExtras", default, skip_serializing_if = "Option::is_none")]
    pub rp_name_extras: Option<String>,
    #[serde(rename = "credentialLabel", default, skip_serializing_if = "Option::is_none")]
    pub credential_label: Option<String>,
    #[serde(rename = "aggregateDevices", default, skip_serializing_if = "Option::is_none")]
    pub aggregate_devices: Option<String>,
    #[serde(rename = "recoveryAssurance", default, skip_serializing_if = "Option::is_none")]
    pub recovery_assurance: Option<String>,
    #[serde(rename = "attestationAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub attestation_algorithms: Option<String>,
    #[serde(rename = "adminEnrolment", default, skip_serializing_if = "Option::is_none")]
    pub admin_enrolment: Option<String>,
    #[serde(rename = "deviceBoundRequired", default, skip_serializing_if = "Option::is_none")]
    pub device_bound_required: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "stsRecoveryPending", default, skip_serializing_if = "Option::is_none")]
    pub sts_recovery_pending: Option<String>,
    #[serde(rename = "stsPasswordResetSource", default, skip_serializing_if = "Option::is_none")]
    pub sts_password_reset_source: Option<String>,
}

impl PasskeyPolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.passkey");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "allowUsernameless",
            attribute: Some("stsPasskeyAllowUsernameless"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requireUsernameless",
            attribute: Some("stsPasskeyRequireUsernameless"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "securityKeyResidentKey",
            attribute: Some("stsPasskeySecurityKeyResidentKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "backupEligibility",
            attribute: Some("stsPasskeyBackupEligibility"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enforcePinLength",
            attribute: Some("stsPasskeyEnforcePinLength"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "minPinLength",
            attribute: Some("stsPasskeyMinPinLength"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pinLengthOnlyIfSupported",
            attribute: Some("stsPasskeyPinLengthOnlyIfSupported"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enforceAttestationAtSignIn",
            attribute: Some("stsPasskeyEnforceAttestationAtSignIn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "postQuantumRequired",
            attribute: Some("stsPasskeyPostQuantumRequired"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "postQuantumAllowCredentials",
            attribute: Some("stsPasskeyPostQuantumAllowCredentials"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registrationAlgorithms",
            attribute: Some("stsPasskeyRegistrationAlgorithms"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registrationMode",
            attribute: Some("stsPasskeyRegistrationMode"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lanes",
            attribute: Some("stsPasskeyLanes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientRules",
            attribute: Some("stsPasskeyClientRules"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "hintsPasskey",
            attribute: Some("stsPasskeyHintsPasskey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "hintsSecurityKey",
            attribute: Some("stsPasskeyHintsSecurityKey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "hintsSignIn",
            attribute: Some("stsPasskeyHintsSignIn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enterpriseSerialAttribute",
            attribute: Some("stsPasskeyEnterpriseSerialAttribute"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userDisplayName",
            attribute: Some("stsPasskeyUserDisplayName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rpNameExtras",
            attribute: Some("stsPasskeyRpNameExtras"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "credentialLabel",
            attribute: Some("stsPasskeyCredentialLabel"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "aggregateDevices",
            attribute: Some("stsPasskeyAggregateDevices"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "recoveryAssurance",
            attribute: Some("stsPasskeyRecoveryAssurance"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "attestationAlgorithms",
            attribute: Some("stsPasskeyAttestationAlgorithms"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "adminEnrolment",
            attribute: Some("stsPasskeyAdminEnrolment"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "deviceBoundRequired",
            attribute: Some("stsPasskeyDeviceBoundRequired"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "precedence",
            attribute: Some("stsPasskeyPrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsRecoveryPending",
            attribute: Some("stsRecoveryPending"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPasswordResetSource",
            attribute: Some("stsPasswordResetSource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What a password must be.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPolicy {
    #[serde(rename = "pwdAttribute", default, skip_serializing_if = "Option::is_none")]
    pub pwd_attribute: Option<Vec<String>>,
    #[serde(rename = "pwdMinLength", default, skip_serializing_if = "Option::is_none")]
    pub pwd_min_length: Option<String>,
    #[serde(rename = "pwdInHistory", default, skip_serializing_if = "Option::is_none")]
    pub pwd_in_history: Option<String>,
    #[serde(rename = "stsPwdMinSymbols", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_min_symbols: Option<String>,
    #[serde(rename = "stsPwdRequireUppercase", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_require_uppercase: Option<String>,
    #[serde(rename = "stsPwdRequireDigit", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_require_digit: Option<String>,
    #[serde(rename = "stsPwdGeneratedLength", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_generated_length: Option<String>,
    #[serde(rename = "stsPwdHashAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_hash_algorithm: Option<String>,
    #[serde(rename = "stsPwdArgon2Memory", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_argon2_memory: Option<String>,
    #[serde(rename = "stsPwdArgon2Iterations", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_argon2_iterations: Option<String>,
    #[serde(rename = "stsPwdArgon2Parallelism", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_argon2_parallelism: Option<String>,
    #[serde(rename = "stsPwdScryptLogN", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_scrypt_log_n: Option<String>,
    #[serde(rename = "stsPwdScryptBlockSize", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_scrypt_block_size: Option<String>,
    #[serde(rename = "stsPwdScryptParallelism", default, skip_serializing_if = "Option::is_none")]
    pub sts_pwd_scrypt_parallelism: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "pwdHistory", default, skip_serializing_if = "Option::is_none")]
    pub pwd_history: Option<Vec<String>>,
    #[serde(rename = "pwdChangedTime", default, skip_serializing_if = "Option::is_none")]
    pub pwd_changed_time: Option<String>,
}

impl PasswordPolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.password");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "pwdAttribute",
            attribute: Some("pwdAttribute"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pwdMinLength",
            attribute: Some("pwdMinLength"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pwdInHistory",
            attribute: Some("pwdInHistory"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdMinSymbols",
            attribute: Some("stsPwdMinSymbols"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdRequireUppercase",
            attribute: Some("stsPwdRequireUppercase"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdRequireDigit",
            attribute: Some("stsPwdRequireDigit"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdGeneratedLength",
            attribute: Some("stsPwdGeneratedLength"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdHashAlgorithm",
            attribute: Some("stsPwdHashAlgorithm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdArgon2Memory",
            attribute: Some("stsPwdArgon2Memory"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdArgon2Iterations",
            attribute: Some("stsPwdArgon2Iterations"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdArgon2Parallelism",
            attribute: Some("stsPwdArgon2Parallelism"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdScryptLogN",
            attribute: Some("stsPwdScryptLogN"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdScryptBlockSize",
            attribute: Some("stsPwdScryptBlockSize"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsPwdScryptParallelism",
            attribute: Some("stsPwdScryptParallelism"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "precedence",
            attribute: Some("stsPasswordPrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pwdHistory",
            attribute: Some("pwdHistory"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pwdChangedTime",
            attribute: Some("pwdChangedTime"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What this service keeps about a person beyond their profile and credentials:
/// federation links, delegation, consent and SPIFFE subjects.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509subject: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509issuer: Option<Vec<String>>,
    #[serde(rename = "x509serialNumber", default, skip_serializing_if = "Option::is_none")]
    pub x509serial_number: Option<Vec<String>>,
    #[serde(rename = "x509notBefore", default, skip_serializing_if = "Option::is_none")]
    pub x509not_before: Option<Vec<String>>,
    #[serde(rename = "x509notAfter", default, skip_serializing_if = "Option::is_none")]
    pub x509not_after: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509fingerprint256: Option<Vec<String>>,
    #[serde(rename = "x509svidsIssued", default, skip_serializing_if = "Option::is_none")]
    pub x509svids_issued: Option<i64>,
    #[serde(rename = "x509firstIssued", default, skip_serializing_if = "Option::is_none")]
    pub x509first_issued: Option<String>,
    #[serde(rename = "x509lastIssued", default, skip_serializing_if = "Option::is_none")]
    pub x509last_issued: Option<String>,
    #[serde(rename = "didSubject", default, skip_serializing_if = "Option::is_none")]
    pub did_subject: Option<Vec<String>>,
    #[serde(rename = "didMethod", default, skip_serializing_if = "Option::is_none")]
    pub did_method: Option<Vec<String>>,
    #[serde(rename = "spiffeSubject", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_subject: Option<Vec<String>>,
    #[serde(rename = "spiffePath", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_path: Option<String>,
    #[serde(rename = "spiffeTrustDomain", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_trust_domain: Option<String>,
    #[serde(rename = "spiffeCredentialStatus", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_credential_status: Option<String>,
    #[serde(rename = "spiffeCredentialStatusReason", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_credential_status_reason: Option<String>,
    #[serde(rename = "spiffeRevokedAt", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_revoked_at: Option<String>,
    #[serde(rename = "authnMethod", default, skip_serializing_if = "Option::is_none")]
    pub authn_method: Option<Vec<String>>,
    #[serde(rename = "mfaAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub mfa_authenticated: Option<bool>,
    #[serde(rename = "mfaLastAuthTime", default, skip_serializing_if = "Option::is_none")]
    pub mfa_last_auth_time: Option<String>,
    #[serde(rename = "federationIssuer", default, skip_serializing_if = "Option::is_none")]
    pub federation_issuer: Option<Vec<String>>,
    #[serde(rename = "federationLink", default, skip_serializing_if = "Option::is_none")]
    pub federation_link: Option<Vec<String>>,
    #[serde(rename = "federationLastSeen", default, skip_serializing_if = "Option::is_none")]
    pub federation_last_seen: Option<String>,
    #[serde(rename = "federationAttribute", default, skip_serializing_if = "Option::is_none")]
    pub federation_attribute: Option<Vec<String>>,
    #[serde(rename = "provisionedBy", default, skip_serializing_if = "Option::is_none")]
    pub provisioned_by: Option<String>,
    #[serde(rename = "oauthConsent", default, skip_serializing_if = "Option::is_none")]
    pub oauth_consent: Option<Vec<String>>,
    #[serde(rename = "oauthConsentWithdrawn", default, skip_serializing_if = "Option::is_none")]
    pub oauth_consent_withdrawn: Option<Vec<String>>,
    #[serde(rename = "oauthConsentApplied", default, skip_serializing_if = "Option::is_none")]
    pub oauth_consent_applied: Option<Vec<String>>,
    #[serde(rename = "bootstrapAdministrator", default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_administrator: Option<bool>,
    #[serde(rename = "consoleClaimedAt", default, skip_serializing_if = "Option::is_none")]
    pub console_claimed_at: Option<String>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(rename = "delegationSemantics", default, skip_serializing_if = "Option::is_none")]
    pub delegation_semantics: Option<Vec<String>>,
    #[serde(rename = "defaultDelegationSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_delegation_semantics: Option<String>,
    #[serde(rename = "authzenApplication", default, skip_serializing_if = "Option::is_none")]
    pub authzen_application: Option<Vec<String>>,
    #[serde(rename = "authzenCallbackUri", default, skip_serializing_if = "Option::is_none")]
    pub authzen_callback_uri: Option<Vec<String>>,
    #[serde(rename = "mailVerified", default, skip_serializing_if = "Option::is_none")]
    pub mail_verified: Option<String>,
    #[serde(rename = "audSub", default, skip_serializing_if = "Option::is_none")]
    pub aud_sub: Option<Vec<String>>,
}

impl PersonRecord {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("person");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "x509subject",
            attribute: Some("x509subject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509issuer",
            attribute: Some("x509issuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509serialNumber",
            attribute: Some("x509serialNumber"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509notBefore",
            attribute: Some("x509notBefore"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509notAfter",
            attribute: Some("x509notAfter"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509fingerprint256",
            attribute: Some("x509fingerprint256"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509svidsIssued",
            attribute: Some("x509svidsIssued"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509firstIssued",
            attribute: Some("x509firstIssued"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509lastIssued",
            attribute: Some("x509lastIssued"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "didSubject",
            attribute: Some("didSubject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "didMethod",
            attribute: Some("didMethod"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffeSubject",
            attribute: Some("spiffeSubject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffePath",
            attribute: Some("spiffePath"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffeTrustDomain",
            attribute: Some("spiffeTrustDomain"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffeCredentialStatus",
            attribute: Some("spiffeCredentialStatus"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffeCredentialStatusReason",
            attribute: Some("spiffeCredentialStatusReason"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spiffeRevokedAt",
            attribute: Some("spiffeRevokedAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authnMethod",
            attribute: Some("authnMethod"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mfaAuthenticated",
            attribute: Some("mfaAuthenticated"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mfaLastAuthTime",
            attribute: Some("mfaLastAuthTime"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationIssuer",
            attribute: Some("federationIssuer"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationLink",
            attribute: Some("federationLink"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationLastSeen",
            attribute: Some("federationLastSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federationAttribute",
            attribute: Some("federationAttribute"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "provisionedBy",
            attribute: Some("stsProvisionedBy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "oauthConsent",
            attribute: Some("oauthConsent"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "oauthConsentWithdrawn",
            attribute: Some("oauthConsentWithdrawn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "oauthConsentApplied",
            attribute: Some("oauthConsentApplied"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "bootstrapAdministrator",
            attribute: Some("stsBootstrapAdministrator"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "consoleClaimedAt",
            attribute: Some("stsConsoleClaimedAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mfaRequired",
            attribute: Some("stsMfaRequired"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "notDelegated",
            attribute: Some("stsNotDelegated"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mayAct",
            attribute: Some("stsMayAct"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "delegationSemantics",
            attribute: Some("stsDelegationSemantics"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "defaultDelegationSemantics",
            attribute: Some("stsDefaultDelegationSemantics"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authzenApplication",
            attribute: Some("stsAuthzenApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authzenCallbackUri",
            attribute: Some("stsAuthzenCallbackUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mailVerified",
            attribute: Some("stsMailVerified"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "audSub",
            attribute: Some("stsAudSub"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What is asked of a person after signing in.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostLoginPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<String>,
    #[serde(rename = "snoozeDays", default, skip_serializing_if = "Option::is_none")]
    pub snooze_days: Option<String>,
    #[serde(rename = "graceDays", default, skip_serializing_if = "Option::is_none")]
    pub grace_days: Option<String>,
    #[serde(rename = "noPasskey", default, skip_serializing_if = "Option::is_none")]
    pub no_passkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(rename = "noPasskeyFallback", default, skip_serializing_if = "Option::is_none")]
    pub no_passkey_fallback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "noPasskeyRole", default, skip_serializing_if = "Option::is_none")]
    pub no_passkey_role: Option<String>,
}

impl PostLoginPolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.postLogin");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "enabled",
            attribute: Some("stsPostLoginEnabled"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "activity",
            attribute: Some("stsPostLoginActivity"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "snoozeDays",
            attribute: Some("stsPostLoginSnoozeDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "graceDays",
            attribute: Some("stsPostLoginGraceDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "noPasskey",
            attribute: Some("stsPostLoginNoPasskey"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "method",
            attribute: Some("stsPostLoginMethod"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "attestation",
            attribute: Some("stsPostLoginAttestation"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "noPasskeyFallback",
            attribute: Some("stsPostLoginNoPasskeyFallback"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "precedence",
            attribute: Some("stsPostLoginPrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "noPasskeyRole",
            attribute: Some("stsPostLoginNoPasskeyRole"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A set of permissions and who holds it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub name: String,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "memberUsers", default, skip_serializing_if = "Option::is_none")]
    pub member_users: Option<Vec<String>>,
    #[serde(rename = "memberGroups", default, skip_serializing_if = "Option::is_none")]
    pub member_groups: Option<Vec<String>>,
    #[serde(rename = "memberApplications", default, skip_serializing_if = "Option::is_none")]
    pub member_applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "roleConferredBy", default, skip_serializing_if = "Option::is_none")]
    pub role_conferred_by: Option<Vec<String>>,
    #[serde(rename = "roleApplication", default, skip_serializing_if = "Option::is_none")]
    pub role_application: Option<String>,
    #[serde(rename = "roleAllowedMemberType", default, skip_serializing_if = "Option::is_none")]
    pub role_allowed_member_type: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Vec<String>>,
    #[serde(rename = "stsOwnerProtected", default, skip_serializing_if = "Option::is_none")]
    pub sts_owner_protected: Option<bool>,
}

impl Role {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("role");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "name",
            attribute: Some("roleName"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "displayName",
            attribute: Some("displayName"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "memberUsers",
            attribute: Some("roleMemberUser"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "memberGroups",
            attribute: Some("roleMemberGroup"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "memberApplications",
            attribute: Some("roleMemberApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "permissions",
            attribute: Some("rolePermission"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "roleConferredBy",
            attribute: Some("roleConferredBy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "roleApplication",
            attribute: Some("roleApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "roleAllowedMemberType",
            attribute: Some("roleAllowedMemberType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "owner",
            attribute: Some("owner"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsOwnerProtected",
            attribute: Some("stsOwnerProtected"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What a SAML service provider is registered with.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlServiceProvider {
    #[serde(rename = "entityIds", default, skip_serializing_if = "Option::is_none")]
    pub entity_ids: Option<Vec<String>>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "assertionConsumerService", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_service: Option<Vec<String>>,
    #[serde(rename = "singleLogoutService", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_service: Option<Vec<String>>,
    #[serde(rename = "nameIdFormat", default, skip_serializing_if = "Option::is_none")]
    pub name_id_format: Option<Vec<String>>,
    #[serde(rename = "responseBinding", default, skip_serializing_if = "Option::is_none")]
    pub response_binding: Option<Vec<String>>,
    #[serde(rename = "signingCertificate", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate: Option<Vec<String>>,
    #[serde(rename = "observedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub observed_signing_certificate: Option<String>,
    #[serde(rename = "authnRequestVerification", default, skip_serializing_if = "Option::is_none")]
    pub authn_request_verification: Option<String>,
    #[serde(rename = "spMetadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata_url: Option<String>,
    #[serde(rename = "spMetadata", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata: Option<String>,
    #[serde(rename = "encryptionCertificate", default, skip_serializing_if = "Option::is_none")]
    pub encryption_certificate: Option<String>,
    #[serde(rename = "sloEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub slo_endpoint: Option<Vec<String>>,
    #[serde(rename = "spNameIdFormat", default, skip_serializing_if = "Option::is_none")]
    pub sp_name_id_format: Option<Vec<String>>,
    #[serde(rename = "spAuthnRequestsSigned", default, skip_serializing_if = "Option::is_none")]
    pub sp_authn_requests_signed: Option<String>,
    #[serde(rename = "spWantAssertionsSigned", default, skip_serializing_if = "Option::is_none")]
    pub sp_want_assertions_signed: Option<String>,
    #[serde(rename = "spWantAssertionsEncrypted", default, skip_serializing_if = "Option::is_none")]
    pub sp_want_assertions_encrypted: Option<String>,
    #[serde(rename = "spMetadataValidUntil", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata_valid_until: Option<String>,
    #[serde(rename = "spMetadataCacheDuration", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata_cache_duration: Option<String>,
    #[serde(rename = "spMetadataConsumedAt", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata_consumed_at: Option<String>,
    #[serde(rename = "spMetadataSignature", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata_signature: Option<String>,
    #[serde(rename = "spMetadataSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub sp_metadata_signing_certificate: Option<String>,
    #[serde(rename = "f2EncryptAssertion", default, skip_serializing_if = "Option::is_none")]
    pub f2_encrypt_assertion: Option<String>,
    #[serde(rename = "f2EncryptionAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub f2_encryption_algorithm: Option<String>,
    #[serde(rename = "f2KeyTransportAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub f2_key_transport_algorithm: Option<String>,
    #[serde(rename = "f2EncryptLogoutNameId", default, skip_serializing_if = "Option::is_none")]
    pub f2_encrypt_logout_name_id: Option<String>,
    #[serde(rename = "f2CustomAttributes", default, skip_serializing_if = "Option::is_none")]
    pub f2_custom_attributes: Option<String>,
    #[serde(rename = "f11CustomAttributes", default, skip_serializing_if = "Option::is_none")]
    pub f11_custom_attributes: Option<String>,
    #[serde(rename = "f2ClaimAttributes", default, skip_serializing_if = "Option::is_none")]
    pub f2_claim_attributes: Option<String>,
    #[serde(rename = "f11ClaimAttributes", default, skip_serializing_if = "Option::is_none")]
    pub f11_claim_attributes: Option<String>,
    #[serde(rename = "f2ClaimsCombine", default, skip_serializing_if = "Option::is_none")]
    pub f2_claims_combine: Option<String>,
    #[serde(rename = "f11ClaimsCombine", default, skip_serializing_if = "Option::is_none")]
    pub f11_claims_combine: Option<String>,
    #[serde(rename = "f2AssertionLifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub f2_assertion_lifetime_min: Option<String>,
    #[serde(rename = "f2SignAssertion", default, skip_serializing_if = "Option::is_none")]
    pub f2_sign_assertion: Option<String>,
    #[serde(rename = "f2SignResponse", default, skip_serializing_if = "Option::is_none")]
    pub f2_sign_response: Option<String>,
    #[serde(rename = "f2NameIdFormat", default, skip_serializing_if = "Option::is_none")]
    pub f2_name_id_format: Option<String>,
    #[serde(rename = "f2ArtifactTtlS", default, skip_serializing_if = "Option::is_none")]
    pub f2_artifact_ttl_s: Option<String>,
    #[serde(rename = "f11AssertionLifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub f11_assertion_lifetime_min: Option<String>,
    #[serde(rename = "f11SignAssertion", default, skip_serializing_if = "Option::is_none")]
    pub f11_sign_assertion: Option<String>,
    #[serde(rename = "f11SignResponse", default, skip_serializing_if = "Option::is_none")]
    pub f11_sign_response: Option<String>,
    #[serde(rename = "f11NameIdFormat", default, skip_serializing_if = "Option::is_none")]
    pub f11_name_id_format: Option<String>,
    #[serde(rename = "f11ArtifactTtlS", default, skip_serializing_if = "Option::is_none")]
    pub f11_artifact_ttl_s: Option<String>,
    #[serde(rename = "f2IdpInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub f2_idp_initiated_sso: Option<String>,
    #[serde(rename = "f2SpInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub f2_sp_initiated_sso: Option<String>,
    #[serde(rename = "f11IdpInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub f11_idp_initiated_sso: Option<String>,
    #[serde(rename = "f11SpInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub f11_sp_initiated_sso: Option<String>,
    #[serde(rename = "f2SsoConsent", default, skip_serializing_if = "Option::is_none")]
    pub f2_sso_consent: Option<String>,
    #[serde(rename = "f11SsoConsent", default, skip_serializing_if = "Option::is_none")]
    pub f11_sso_consent: Option<String>,
    #[serde(rename = "authnRequestSigned", default, skip_serializing_if = "Option::is_none")]
    pub authn_request_signed: Option<String>,
}

impl SamlServiceProvider {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "entityIds",
            attribute: Some("samlEntityId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionConsumerServices",
            attribute: Some("samlAcsEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionConsumerService",
            attribute: Some("samlAssertionConsumerService"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "singleLogoutService",
            attribute: Some("samlSingleLogoutService"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "nameIdFormat",
            attribute: Some("samlNameIdFormat"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "responseBinding",
            attribute: Some("samlResponseBinding"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signingCertificate",
            attribute: Some("samlSigningCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "observedSigningCertificate",
            attribute: Some("samlObservedSigningCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authnRequestVerification",
            attribute: Some("samlAuthnRequestVerification"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadataUrl",
            attribute: Some("samlSpMetadataUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadata",
            attribute: Some("samlSpMetadata"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "encryptionCertificate",
            attribute: Some("samlEncryptionCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sloEndpoint",
            attribute: Some("samlSloEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spNameIdFormat",
            attribute: Some("samlSpNameIdFormat"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spAuthnRequestsSigned",
            attribute: Some("samlSpAuthnRequestsSigned"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spWantAssertionsSigned",
            attribute: Some("samlSpWantAssertionsSigned"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spWantAssertionsEncrypted",
            attribute: Some("samlSpWantAssertionsEncrypted"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadataValidUntil",
            attribute: Some("samlSpMetadataValidUntil"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadataCacheDuration",
            attribute: Some("samlSpMetadataCacheDuration"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadataConsumedAt",
            attribute: Some("samlSpMetadataConsumedAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadataSignature",
            attribute: Some("samlSpMetadataSignature"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spMetadataSigningCertificate",
            attribute: Some("samlSpMetadataSigningCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2EncryptAssertion",
            attribute: Some("saml2EncryptAssertion"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2EncryptionAlgorithm",
            attribute: Some("saml2EncryptionAlgorithm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2KeyTransportAlgorithm",
            attribute: Some("saml2KeyTransportAlgorithm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2EncryptLogoutNameId",
            attribute: Some("saml2EncryptLogoutNameId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2CustomAttributes",
            attribute: Some("saml2CustomAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11CustomAttributes",
            attribute: Some("saml11CustomAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2ClaimAttributes",
            attribute: Some("saml2ClaimAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11ClaimAttributes",
            attribute: Some("saml11ClaimAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2ClaimsCombine",
            attribute: Some("saml2ClaimsCombine"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11ClaimsCombine",
            attribute: Some("saml11ClaimsCombine"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2AssertionLifetimeMin",
            attribute: Some("saml2AssertionLifetimeMin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2SignAssertion",
            attribute: Some("saml2SignAssertion"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2SignResponse",
            attribute: Some("saml2SignResponse"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2NameIdFormat",
            attribute: Some("saml2NameIdFormat"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2ArtifactTtlS",
            attribute: Some("saml2ArtifactTtlS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11AssertionLifetimeMin",
            attribute: Some("saml11AssertionLifetimeMin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11SignAssertion",
            attribute: Some("saml11SignAssertion"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11SignResponse",
            attribute: Some("saml11SignResponse"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11NameIdFormat",
            attribute: Some("saml11NameIdFormat"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11ArtifactTtlS",
            attribute: Some("saml11ArtifactTtlS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2IdpInitiatedSso",
            attribute: Some("saml2IdpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2SpInitiatedSso",
            attribute: Some("saml2SpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11IdpInitiatedSso",
            attribute: Some("saml11IdpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11SpInitiatedSso",
            attribute: Some("saml11SpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f2SsoConsent",
            attribute: Some("saml2SsoConsent"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "f11SsoConsent",
            attribute: Some("saml11SsoConsent"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authnRequestSigned",
            attribute: Some("samlAuthnRequestSigned"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Where people are provisioned by SCIM.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimProvisioningTarget {
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<Vec<String>>,
    #[serde(rename = "clientBaseUrl", default, skip_serializing_if = "Option::is_none")]
    pub client_base_url: Option<String>,
    #[serde(rename = "clientEnabled", default, skip_serializing_if = "Option::is_none")]
    pub client_enabled: Option<String>,
    #[serde(rename = "clientAuthMethod", default, skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<String>,
    #[serde(rename = "clientUsername", default, skip_serializing_if = "Option::is_none")]
    pub client_username: Option<String>,
    #[serde(rename = "clientPassword", default, skip_serializing_if = "Option::is_none")]
    pub client_password: Option<String>,
    #[serde(rename = "clientTokenEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub client_token_endpoint: Option<String>,
    #[serde(rename = "clientOAuthClientId", default, skip_serializing_if = "Option::is_none")]
    pub client_o_auth_client_id: Option<String>,
    #[serde(rename = "clientOAuthClientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_o_auth_client_secret: Option<String>,
    #[serde(rename = "clientOAuthClientAuth", default, skip_serializing_if = "Option::is_none")]
    pub client_o_auth_client_auth: Option<String>,
    #[serde(rename = "clientOAuthScope", default, skip_serializing_if = "Option::is_none")]
    pub client_o_auth_scope: Option<String>,
    #[serde(rename = "clientOAuthResource", default, skip_serializing_if = "Option::is_none")]
    pub client_o_auth_resource: Option<String>,
    #[serde(rename = "clientTlsSource", default, skip_serializing_if = "Option::is_none")]
    pub client_tls_source: Option<String>,
    #[serde(rename = "clientTlsCertificate", default, skip_serializing_if = "Option::is_none")]
    pub client_tls_certificate: Option<String>,
    #[serde(rename = "clientTlsPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub client_tls_private_key: Option<String>,
    #[serde(rename = "clientCaCertificates", default, skip_serializing_if = "Option::is_none")]
    pub client_ca_certificates: Option<String>,
    #[serde(rename = "clientScopeMode", default, skip_serializing_if = "Option::is_none")]
    pub client_scope_mode: Option<String>,
    #[serde(rename = "clientScopeGroups", default, skip_serializing_if = "Option::is_none")]
    pub client_scope_groups: Option<Vec<String>>,
    #[serde(rename = "clientScopeFilter", default, skip_serializing_if = "Option::is_none")]
    pub client_scope_filter: Option<String>,
    #[serde(rename = "clientGroupMode", default, skip_serializing_if = "Option::is_none")]
    pub client_group_mode: Option<String>,
    #[serde(rename = "clientGroups", default, skip_serializing_if = "Option::is_none")]
    pub client_groups: Option<Vec<String>>,
    #[serde(rename = "clientDeprovision", default, skip_serializing_if = "Option::is_none")]
    pub client_deprovision: Option<String>,
    #[serde(rename = "clientReconcileMinutes", default, skip_serializing_if = "Option::is_none")]
    pub client_reconcile_minutes: Option<String>,
    #[serde(rename = "clientJurisdiction", default, skip_serializing_if = "Option::is_none")]
    pub client_jurisdiction: Option<String>,
    #[serde(rename = "clientCells", default, skip_serializing_if = "Option::is_none")]
    pub client_cells: Option<Vec<String>>,
    #[serde(rename = "clientMaxRequestsPerSecond", default, skip_serializing_if = "Option::is_none")]
    pub client_max_requests_per_second: Option<String>,
}

impl ScimProvisioningTarget {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "clientId",
            attribute: Some("scimClientId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientBaseUrl",
            attribute: Some("scimClientBaseUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientEnabled",
            attribute: Some("scimClientEnabled"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientAuthMethod",
            attribute: Some("scimClientAuthMethod"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientUsername",
            attribute: Some("scimClientUsername"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientPassword",
            attribute: Some("scimClientPassword"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientTokenEndpoint",
            attribute: Some("scimClientTokenEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientOAuthClientId",
            attribute: Some("scimClientOAuthClientId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientOAuthClientSecret",
            attribute: Some("scimClientOAuthClientSecret"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientOAuthClientAuth",
            attribute: Some("scimClientOAuthClientAuth"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientOAuthScope",
            attribute: Some("scimClientOAuthScope"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientOAuthResource",
            attribute: Some("scimClientOAuthResource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientTlsSource",
            attribute: Some("scimClientTlsSource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientTlsCertificate",
            attribute: Some("scimClientTlsCertificate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientTlsPrivateKey",
            attribute: Some("scimClientTlsPrivateKey"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientCaCertificates",
            attribute: Some("scimClientCaCertificates"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientScopeMode",
            attribute: Some("scimClientScopeMode"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientScopeGroups",
            attribute: Some("scimClientScopeGroups"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientScopeFilter",
            attribute: Some("scimClientScopeFilter"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientGroupMode",
            attribute: Some("scimClientGroupMode"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientGroups",
            attribute: Some("scimClientGroups"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientDeprovision",
            attribute: Some("scimClientDeprovision"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientReconcileMinutes",
            attribute: Some("scimClientReconcileMinutes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientJurisdiction",
            attribute: Some("scimClientJurisdiction"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientCells",
            attribute: Some("scimClientCells"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientMaxRequestsPerSecond",
            attribute: Some("scimClientMaxRequestsPerSecond"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Where a rotated password is pushed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretDestination {
    #[serde(rename = "destProvider", default, skip_serializing_if = "Option::is_none")]
    pub dest_provider: Option<String>,
    #[serde(rename = "destPayload", default, skip_serializing_if = "Option::is_none")]
    pub dest_payload: Option<String>,
    #[serde(rename = "destRegion", default, skip_serializing_if = "Option::is_none")]
    pub dest_region: Option<String>,
    #[serde(rename = "destProject", default, skip_serializing_if = "Option::is_none")]
    pub dest_project: Option<String>,
    #[serde(rename = "destEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub dest_endpoint: Option<String>,
    #[serde(rename = "destMount", default, skip_serializing_if = "Option::is_none")]
    pub dest_mount: Option<String>,
    #[serde(rename = "destField", default, skip_serializing_if = "Option::is_none")]
    pub dest_field: Option<String>,
    #[serde(rename = "destDirectory", default, skip_serializing_if = "Option::is_none")]
    pub dest_directory: Option<String>,
    #[serde(rename = "destCaCertificates", default, skip_serializing_if = "Option::is_none")]
    pub dest_ca_certificates: Option<String>,
    #[serde(rename = "destCredential", default, skip_serializing_if = "Option::is_none")]
    pub dest_credential: Option<String>,
}

impl SecretDestination {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "destProvider",
            attribute: Some("secretDestProvider"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destPayload",
            attribute: Some("secretDestPayload"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destRegion",
            attribute: Some("secretDestRegion"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destProject",
            attribute: Some("secretDestProject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destEndpoint",
            attribute: Some("secretDestEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destMount",
            attribute: Some("secretDestMount"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destField",
            attribute: Some("secretDestField"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destDirectory",
            attribute: Some("secretDestDirectory"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destCaCertificates",
            attribute: Some("secretDestCaCertificates"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "destCredential",
            attribute: Some("secretDestCredential"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
    ];
}

/// An account a program uses, rotated by this service and owned by a person.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<String>>,
    #[serde(rename = "secretDestination", default, skip_serializing_if = "Option::is_none")]
    pub secret_destination: Option<String>,
    #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(rename = "rotationFailures", default, skip_serializing_if = "Option::is_none")]
    pub rotation_failures: Option<i64>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "passwordRotatedAt", default, skip_serializing_if = "Option::is_none")]
    pub password_rotated_at: Option<String>,
    #[serde(rename = "previousPassword", default, skip_serializing_if = "Option::is_none")]
    pub previous_password: Option<String>,
    #[serde(rename = "previousPasswordExpires", default, skip_serializing_if = "Option::is_none")]
    pub previous_password_expires: Option<String>,
    #[serde(rename = "rotationLastError", default, skip_serializing_if = "Option::is_none")]
    pub rotation_last_error: Option<String>,
    #[serde(rename = "rotationLastAttempt", default, skip_serializing_if = "Option::is_none")]
    pub rotation_last_attempt: Option<String>,
    #[serde(rename = "ownerProtected", default, skip_serializing_if = "Option::is_none")]
    pub owner_protected: Option<bool>,
    #[serde(rename = "serviceAccountPolicy", default, skip_serializing_if = "Option::is_none")]
    pub service_account_policy: Option<String>,
}

impl ServiceAccount {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("serviceAccount");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "owners",
            attribute: Some("stsServiceAccountOwner"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "secretDestination",
            attribute: Some("stsSecretDestination"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "secretName",
            attribute: Some("stsSecretName"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationFailures",
            attribute: Some("stsRotationFailures"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "serviceAccount",
            attribute: Some("stsServiceAccount"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "passwordRotatedAt",
            attribute: Some("stsPasswordRotatedAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "previousPassword",
            attribute: Some("stsPreviousPassword"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "previousPasswordExpires",
            attribute: Some("stsPreviousPasswordExpires"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationLastError",
            attribute: Some("stsRotationLastError"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationLastAttempt",
            attribute: Some("stsRotationLastAttempt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "ownerProtected",
            attribute: Some("stsOwnerProtected"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "serviceAccountPolicy",
            attribute: Some("stsServiceAccountPolicy"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What a service account may do.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountPolicy {
    #[serde(rename = "exemptFromSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub exempt_from_second_factor: Option<String>,
    #[serde(rename = "allowBrowserSignIn", default, skip_serializing_if = "Option::is_none")]
    pub allow_browser_sign_in: Option<String>,
    #[serde(rename = "allowLdapBind", default, skip_serializing_if = "Option::is_none")]
    pub allow_ldap_bind: Option<bool>,
    #[serde(rename = "allowWsTrust", default, skip_serializing_if = "Option::is_none")]
    pub allow_ws_trust: Option<bool>,
    #[serde(rename = "allowScim", default, skip_serializing_if = "Option::is_none")]
    pub allow_scim: Option<bool>,
    #[serde(rename = "allowSsf", default, skip_serializing_if = "Option::is_none")]
    pub allow_ssf: Option<bool>,
    #[serde(rename = "allowEst", default, skip_serializing_if = "Option::is_none")]
    pub allow_est: Option<bool>,
    #[serde(rename = "allowKerberos", default, skip_serializing_if = "Option::is_none")]
    pub allow_kerberos: Option<bool>,
    #[serde(rename = "allowPasswordGrant", default, skip_serializing_if = "Option::is_none")]
    pub allow_password_grant: Option<bool>,
    #[serde(rename = "rotationEnabled", default, skip_serializing_if = "Option::is_none")]
    pub rotation_enabled: Option<String>,
    #[serde(rename = "rotationIntervalDays", default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval_days: Option<String>,
    #[serde(rename = "rotationOverlapMinutes", default, skip_serializing_if = "Option::is_none")]
    pub rotation_overlap_minutes: Option<String>,
    #[serde(rename = "generatedLength", default, skip_serializing_if = "Option::is_none")]
    pub generated_length: Option<String>,
    #[serde(rename = "requireOwner", default, skip_serializing_if = "Option::is_none")]
    pub require_owner: Option<String>,
    #[serde(rename = "rotationAlarmFailures", default, skip_serializing_if = "Option::is_none")]
    pub rotation_alarm_failures: Option<String>,
    #[serde(rename = "stsServiceAccountPrecedence", default, skip_serializing_if = "Option::is_none")]
    pub sts_service_account_precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
}

impl ServiceAccountPolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("policy.serviceAccount");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "exemptFromSecondFactor",
            attribute: Some("stsSvcAcctExemptFromSecondFactor"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowBrowserSignIn",
            attribute: Some("stsSvcAcctAllowBrowserSignIn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowLdapBind",
            attribute: Some("stsSvcAcctAllowLdapBind"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowWsTrust",
            attribute: Some("stsSvcAcctAllowWsTrust"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowScim",
            attribute: Some("stsSvcAcctAllowScim"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowSsf",
            attribute: Some("stsSvcAcctAllowSsf"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowEst",
            attribute: Some("stsSvcAcctAllowEst"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowKerberos",
            attribute: Some("stsSvcAcctAllowKerberos"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowPasswordGrant",
            attribute: Some("stsSvcAcctAllowPasswordGrant"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationEnabled",
            attribute: Some("stsSvcAcctRotationEnabled"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationIntervalDays",
            attribute: Some("stsSvcAcctRotationIntervalDays"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationOverlapMinutes",
            attribute: Some("stsSvcAcctRotationOverlapMinutes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "generatedLength",
            attribute: Some("stsSvcAcctGeneratedLength"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "requireOwner",
            attribute: Some("stsSvcAcctRequireOwner"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "rotationAlarmFailures",
            attribute: Some("stsSvcAcctRotationAlarmFailures"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "stsServiceAccountPrecedence",
            attribute: Some("stsServiceAccountPrecedence"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// An authenticated identity: the internal record every issued artifact is a
/// projection of.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: String,
    pub username: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    pub authenticated: bool,
    #[serde(rename = "authTime")]
    pub auth_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(rename = "assuranceLevel", default, skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<String>,
    #[serde(rename = "startedThrough")]
    pub started_through: String,
    #[serde(rename = "startedAt")]
    pub started_at: i64,
    pub expires: i64,
    #[serde(rename = "lastSeenAt")]
    pub last_seen_at: i64,
    pub events: Vec<AuthenticationEvent>,
    #[serde(rename = "eventsDropped", default, skip_serializing_if = "Option::is_none")]
    pub events_dropped: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
    #[serde(rename = "relyingPartySurface", default, skip_serializing_if = "Option::is_none")]
    pub relying_party_surface: Option<String>,
    #[serde(rename = "relyingPartyLabel", default, skip_serializing_if = "Option::is_none")]
    pub relying_party_label: Option<String>,
    #[serde(rename = "relyingPartyClientId", default, skip_serializing_if = "Option::is_none")]
    pub relying_party_client_id: Option<String>,
    #[serde(rename = "relyingPartyRenewals", default, skip_serializing_if = "Option::is_none")]
    pub relying_party_renewals: Option<i64>,
    #[serde(rename = "relyingPartyRenewedAt", default, skip_serializing_if = "Option::is_none")]
    pub relying_party_renewed_at: Option<i64>,
    #[serde(rename = "apiCalls", default, skip_serializing_if = "Option::is_none")]
    pub api_calls: Option<i64>,
    #[serde(rename = "accountSetId", default, skip_serializing_if = "Option::is_none")]
    pub account_set_id: Option<String>,
}

impl Session {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Record("authn/authn.ts startSession()");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "id",
            attribute: None,
            on: None,
            key: Some("id"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "username",
            attribute: None,
            on: None,
            key: Some("user.username"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "subjectId",
            attribute: None,
            on: None,
            key: Some("subjectId"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authenticated",
            attribute: None,
            on: None,
            key: Some("authenticated"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authTime",
            attribute: None,
            on: None,
            key: Some("authTime"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "methods",
            attribute: None,
            on: None,
            key: Some("amr"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assuranceLevel",
            attribute: None,
            on: None,
            key: Some("acr"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "startedThrough",
            attribute: None,
            on: None,
            key: Some("via"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "startedAt",
            attribute: None,
            on: None,
            key: Some("startedAt"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "expires",
            attribute: None,
            on: None,
            key: Some("expires"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSeenAt",
            attribute: None,
            on: None,
            key: Some("lastSeenAt"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "events",
            attribute: None,
            on: None,
            key: Some("events"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "eventsDropped",
            attribute: None,
            on: None,
            key: Some("eventsDropped"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "sub",
            attribute: None,
            on: None,
            key: Some("user.sub"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "derivedFrom",
            attribute: None,
            on: None,
            key: Some("derivedFrom"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "relyingPartySurface",
            attribute: None,
            on: None,
            key: Some("rpSurface"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "relyingPartyLabel",
            attribute: None,
            on: None,
            key: Some("rpLabel"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "relyingPartyClientId",
            attribute: None,
            on: None,
            key: Some("rpClientId"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "relyingPartyRenewals",
            attribute: None,
            on: None,
            key: Some("rpRenewals"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "relyingPartyRenewedAt",
            attribute: None,
            on: None,
            key: Some("rpRenewedAt"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "apiCalls",
            attribute: None,
            on: None,
            key: Some("calls"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "accountSetId",
            attribute: None,
            on: None,
            key: Some("accountSetId"),
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A Shared Signals receiver or transmitter partner.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSignalsReceiver {
    #[serde(rename = "receiverId", default, skip_serializing_if = "Option::is_none")]
    pub receiver_id: Option<Vec<String>>,
    #[serde(rename = "deliveryEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub delivery_endpoint: Option<Vec<String>>,
    #[serde(rename = "allowedEvents", default, skip_serializing_if = "Option::is_none")]
    pub allowed_events: Option<Vec<String>>,
    #[serde(rename = "caepIncludeReasons", default, skip_serializing_if = "Option::is_none")]
    pub caep_include_reasons: Option<String>,
    #[serde(rename = "caepReasonLanguage", default, skip_serializing_if = "Option::is_none")]
    pub caep_reason_language: Option<String>,
    #[serde(rename = "caepOmitEventTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub caep_omit_event_timestamp: Option<String>,
    #[serde(rename = "riscIncludeReasons", default, skip_serializing_if = "Option::is_none")]
    pub risc_include_reasons: Option<String>,
    #[serde(rename = "riscReasonLanguage", default, skip_serializing_if = "Option::is_none")]
    pub risc_reason_language: Option<String>,
    #[serde(rename = "riscOmitEventTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub risc_omit_event_timestamp: Option<String>,
    #[serde(rename = "signingAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub signing_algorithm: Option<String>,
    #[serde(rename = "minVerificationInterval", default, skip_serializing_if = "Option::is_none")]
    pub min_verification_interval: Option<String>,
    #[serde(rename = "inactivityTimeoutS", default, skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout_s: Option<String>,
    #[serde(rename = "inactivityAction", default, skip_serializing_if = "Option::is_none")]
    pub inactivity_action: Option<String>,
    #[serde(rename = "verificationEveryS", default, skip_serializing_if = "Option::is_none")]
    pub verification_every_s: Option<String>,
    #[serde(rename = "streamStatusOnCreate", default, skip_serializing_if = "Option::is_none")]
    pub stream_status_on_create: Option<String>,
    #[serde(rename = "maxStreams", default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<String>,
    #[serde(rename = "maxSubjectsPerStream", default, skip_serializing_if = "Option::is_none")]
    pub max_subjects_per_stream: Option<String>,
    #[serde(rename = "maxQueuedEvents", default, skip_serializing_if = "Option::is_none")]
    pub max_queued_events: Option<String>,
    #[serde(rename = "pollMaxEvents", default, skip_serializing_if = "Option::is_none")]
    pub poll_max_events: Option<String>,
    #[serde(rename = "deadLetterMaxPerStream", default, skip_serializing_if = "Option::is_none")]
    pub dead_letter_max_per_stream: Option<String>,
    #[serde(rename = "pushTimeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub push_timeout_ms: Option<String>,
    #[serde(rename = "pushRetries", default, skip_serializing_if = "Option::is_none")]
    pub push_retries: Option<String>,
    #[serde(rename = "pushRetryDelayMs", default, skip_serializing_if = "Option::is_none")]
    pub push_retry_delay_ms: Option<String>,
}

impl SharedSignalsReceiver {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "receiverId",
            attribute: Some("ssfReceiverId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "deliveryEndpoint",
            attribute: Some("ssfDeliveryEndpoint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowedEvents",
            attribute: Some("ssfAllowedEvents"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "caepIncludeReasons",
            attribute: Some("ssfCaepIncludeReasons"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "caepReasonLanguage",
            attribute: Some("ssfCaepReasonLanguage"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "caepOmitEventTimestamp",
            attribute: Some("ssfCaepOmitEventTimestamp"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "riscIncludeReasons",
            attribute: Some("ssfRiscIncludeReasons"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "riscReasonLanguage",
            attribute: Some("ssfRiscReasonLanguage"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "riscOmitEventTimestamp",
            attribute: Some("ssfRiscOmitEventTimestamp"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signingAlgorithm",
            attribute: Some("ssfSigningAlgorithm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "minVerificationInterval",
            attribute: Some("ssfMinVerificationInterval"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "inactivityTimeoutS",
            attribute: Some("ssfInactivityTimeoutS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "inactivityAction",
            attribute: Some("ssfInactivityAction"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "verificationEveryS",
            attribute: Some("ssfVerificationEveryS"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "streamStatusOnCreate",
            attribute: Some("ssfStreamStatusOnCreate"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "maxStreams",
            attribute: Some("ssfMaxStreams"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "maxSubjectsPerStream",
            attribute: Some("ssfMaxSubjectsPerStream"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "maxQueuedEvents",
            attribute: Some("ssfMaxQueuedEvents"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pollMaxEvents",
            attribute: Some("ssfPollMaxEvents"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "deadLetterMaxPerStream",
            attribute: Some("ssfDeadLetterMaxPerStream"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pushTimeoutMs",
            attribute: Some("ssfPushTimeoutMs"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pushRetries",
            attribute: Some("ssfPushRetries"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pushRetryDelayMs",
            attribute: Some("ssfPushRetryDelayMs"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A certificate authority a realm trusts to sign what it is sent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerTrustAnchor {
    pub certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(rename = "addedBy", default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

impl SignerTrustAnchor {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("signerTrustAnchor");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "certificate",
            attribute: Some("stsTrustAnchorCertificate"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "fingerprint",
            attribute: Some("stsTrustAnchorFingerprint"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "addedBy",
            attribute: Some("stsTrustAnchorAddedBy"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "kind",
            attribute: Some("stsSignerTrustAnchorKind"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "purpose",
            attribute: Some("stsSignerTrustAnchorPurpose"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
    ];
}

/// A SPIFFE registration entry.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiffeRegistration {
    #[serde(rename = "entryId", default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<Vec<String>>,
    #[serde(rename = "x509SvidTtl", default, skip_serializing_if = "Option::is_none")]
    pub x509_svid_ttl: Option<String>,
    #[serde(rename = "jwtSvidTtl", default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_ttl: Option<String>,
    #[serde(rename = "dnsName", default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<Vec<String>>,
    #[serde(rename = "federatesWith", default, skip_serializing_if = "Option::is_none")]
    pub federates_with: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downstream: Option<String>,
    #[serde(rename = "storeSvid", default, skip_serializing_if = "Option::is_none")]
    pub store_svid: Option<String>,
    #[serde(rename = "entryExpiresAt", default, skip_serializing_if = "Option::is_none")]
    pub entry_expires_at: Option<String>,
    #[serde(rename = "revisionNumber", default, skip_serializing_if = "Option::is_none")]
    pub revision_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "svidsIssued", default, skip_serializing_if = "Option::is_none")]
    pub svids_issued: Option<String>,
    #[serde(rename = "lastSvidAt", default, skip_serializing_if = "Option::is_none")]
    pub last_svid_at: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "attestationType", default, skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<String>,
    #[serde(rename = "agentSelector", default, skip_serializing_if = "Option::is_none")]
    pub agent_selector: Option<Vec<String>>,
    #[serde(rename = "agentBanned", default, skip_serializing_if = "Option::is_none")]
    pub agent_banned: Option<String>,
    #[serde(rename = "agentCanReattest", default, skip_serializing_if = "Option::is_none")]
    pub agent_can_reattest: Option<String>,
    #[serde(rename = "agentSvidHash", default, skip_serializing_if = "Option::is_none")]
    pub agent_svid_hash: Option<String>,
    #[serde(rename = "agentExpiresAt", default, skip_serializing_if = "Option::is_none")]
    pub agent_expires_at: Option<String>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<String>,
}

impl SpiffeRegistration {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("spiffe");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "entryId",
            attribute: Some("spiffeEntryId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "cn",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "id",
            attribute: Some("spiffeId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "parentId",
            attribute: Some("spiffeParentId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "selector",
            attribute: Some("spiffeSelector"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "x509SvidTtl",
            attribute: Some("spiffeX509SvidTtl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jwtSvidTtl",
            attribute: Some("spiffeJwtSvidTtl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "dnsName",
            attribute: Some("spiffeDnsName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "federatesWith",
            attribute: Some("spiffeFederatesWith"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "hint",
            attribute: Some("spiffeHint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "admin",
            attribute: Some("spiffeAdmin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "downstream",
            attribute: Some("spiffeDownstream"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "storeSvid",
            attribute: Some("spiffeStoreSvid"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "entryExpiresAt",
            attribute: Some("spiffeEntryExpiresAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "revisionNumber",
            attribute: Some("spiffeRevisionNumber"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "origin",
            attribute: Some("spiffeOrigin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "svidsIssued",
            attribute: Some("spiffeSvidsIssued"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSvidAt",
            attribute: Some("spiffeLastSvidAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "createdAt",
            attribute: Some("spiffeCreatedAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "agentId",
            attribute: Some("spiffeAgentId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "attestationType",
            attribute: Some("spiffeAttestationType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "agentSelector",
            attribute: Some("spiffeAgentSelector"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "agentBanned",
            attribute: Some("spiffeAgentBanned"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "agentCanReattest",
            attribute: Some("spiffeAgentCanReattest"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "agentSvidHash",
            attribute: Some("spiffeAgentSvidHash"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "agentExpiresAt",
            attribute: Some("spiffeAgentExpiresAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "firstSeen",
            attribute: Some("spiffeFirstSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSeen",
            attribute: Some("spiffeLastSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "attestations",
            attribute: Some("spiffeAttestations"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A certificate authority a realm trusts for client certificates.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    pub certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(rename = "addedBy", default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

impl TrustAnchor {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("trustAnchor");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "certificate",
            attribute: Some("stsTrustAnchorCertificate"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "fingerprint",
            attribute: Some("stsTrustAnchorFingerprint"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "addedBy",
            attribute: Some("stsTrustAnchorAddedBy"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
    ];
}

/// A person this service authenticates, as every protocol projects them.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    #[serde(rename = "entryUuid")]
    pub entry_uuid: String,
    pub username: String,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "givenName", default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(rename = "familyName", default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "preferredLanguage", default, skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<Vec<String>>,
    #[serde(rename = "employeeType", default, skip_serializing_if = "Option::is_none")]
    pub employee_type: Option<Vec<String>>,
    #[serde(rename = "telephoneNumber", default, skip_serializing_if = "Option::is_none")]
    pub telephone_number: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub st: Option<Vec<String>>,
    #[serde(rename = "postalCode", default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
    #[serde(rename = "postalAddress", default, skip_serializing_if = "Option::is_none")]
    pub postal_address: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub o: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ou: Option<Vec<String>>,
    #[serde(rename = "departmentNumber", default, skip_serializing_if = "Option::is_none")]
    pub department_number: Option<Vec<String>>,
    #[serde(rename = "employeeNumber", default, skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
    #[serde(rename = "labeledURI", default, skip_serializing_if = "Option::is_none")]
    pub labeled_uri: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<Vec<String>>,
    #[serde(rename = "schacDateOfBirth", default, skip_serializing_if = "Option::is_none")]
    pub schac_date_of_birth: Option<String>,
    #[serde(rename = "schacCountryOfCitizenship", default, skip_serializing_if = "Option::is_none")]
    pub schac_country_of_citizenship: Option<Vec<String>>,
    #[serde(rename = "schacPersonalTitle", default, skip_serializing_if = "Option::is_none")]
    pub schac_personal_title: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salutation: Option<Vec<String>>,
    #[serde(rename = "birthFamilyName", default, skip_serializing_if = "Option::is_none")]
    pub birth_family_name: Option<Vec<String>>,
    #[serde(rename = "birthGivenName", default, skip_serializing_if = "Option::is_none")]
    pub birth_given_name: Option<Vec<String>>,
    #[serde(rename = "birthMiddleName", default, skip_serializing_if = "Option::is_none")]
    pub birth_middle_name: Option<Vec<String>>,
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    #[serde(rename = "placeOfBirthCountry", default, skip_serializing_if = "Option::is_none")]
    pub place_of_birth_country: Option<String>,
    #[serde(rename = "placeOfBirthRegion", default, skip_serializing_if = "Option::is_none")]
    pub place_of_birth_region: Option<String>,
    #[serde(rename = "placeOfBirthLocality", default, skip_serializing_if = "Option::is_none")]
    pub place_of_birth_locality: Option<String>,
    #[serde(rename = "schacGender", default, skip_serializing_if = "Option::is_none")]
    pub schac_gender: Option<String>,
    #[serde(rename = "middleName", default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(rename = "timeZone", default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    #[serde(rename = "pictureUrl", default, skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
    #[serde(rename = "profileUrl", default, skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,
    #[serde(rename = "scimExternalId", default, skip_serializing_if = "Option::is_none")]
    pub scim_external_id: Option<String>,
    #[serde(rename = "userPrincipalName", default, skip_serializing_if = "Option::is_none")]
    pub user_principal_name: Option<String>,
}

impl User {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("person");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "entryUuid",
            attribute: Some("entryUUID"),
            on: Some("operational"),
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "username",
            attribute: Some("uid"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "displayName",
            attribute: Some("displayName"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "givenName",
            attribute: Some("givenName"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "familyName",
            attribute: Some("sn"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "email",
            attribute: Some("mail"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "preferredLanguage",
            attribute: Some("preferredLanguage"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "cn",
            attribute: Some("cn"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "title",
            attribute: Some("title"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "employeeType",
            attribute: Some("employeeType"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "telephoneNumber",
            attribute: Some("telephoneNumber"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "mobile",
            attribute: Some("mobile"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "street",
            attribute: Some("street"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "l",
            attribute: Some("l"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "st",
            attribute: Some("st"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "postalCode",
            attribute: Some("postalCode"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "c",
            attribute: Some("c"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "postalAddress",
            attribute: Some("postalAddress"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "o",
            attribute: Some("o"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "ou",
            attribute: Some("ou"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "departmentNumber",
            attribute: Some("departmentNumber"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "employeeNumber",
            attribute: Some("employeeNumber"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "labeledURI",
            attribute: Some("labeledURI"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "manager",
            attribute: Some("manager"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "schacDateOfBirth",
            attribute: Some("schacDateOfBirth"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "schacCountryOfCitizenship",
            attribute: Some("schacCountryOfCitizenship"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "schacPersonalTitle",
            attribute: Some("schacPersonalTitle"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "salutation",
            attribute: Some("salutation"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "birthFamilyName",
            attribute: Some("birthFamilyName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "birthGivenName",
            attribute: Some("birthGivenName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "birthMiddleName",
            attribute: Some("birthMiddleName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "alsoKnownAs",
            attribute: Some("alsoKnownAs"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "placeOfBirthCountry",
            attribute: Some("placeOfBirthCountry"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "placeOfBirthRegion",
            attribute: Some("placeOfBirthRegion"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "placeOfBirthLocality",
            attribute: Some("placeOfBirthLocality"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "schacGender",
            attribute: Some("schacGender"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "middleName",
            attribute: Some("middleName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "timeZone",
            attribute: Some("timeZone"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "pictureUrl",
            attribute: Some("pictureUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "profileUrl",
            attribute: Some("profileUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "scimExternalId",
            attribute: Some("scimExternalId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "userPrincipalName",
            attribute: Some("userPrincipalName"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Decentralized identifiers and verifiable credentials.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiableCredentialPartner {
    #[serde(rename = "credentialClaimAttributes", default, skip_serializing_if = "Option::is_none")]
    pub credential_claim_attributes: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<Vec<String>>,
    #[serde(rename = "publicKeyJwk", default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Vec<String>>,
    #[serde(rename = "privateKeys", default, skip_serializing_if = "Option::is_none")]
    pub private_keys: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<String>>,
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
}

impl VerifiableCredentialPartner {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "credentialClaimAttributes",
            attribute: Some("vcCredentialClaimAttributes"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "clientId",
            attribute: Some("oid4vpClientId"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "publicKeyJwk",
            attribute: Some("didPublicKeyJwk"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "privateKeys",
            attribute: Some("didPrivateKeys"),
            on: None,
            key: None,
            transform: None,
            secret: true,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "service",
            attribute: Some("didService"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "alsoKnownAs",
            attribute: Some("didAlsoKnownAs"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// What a WS-Federation relying party is registered with.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsFederationRelyingParty {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<String>>,
    #[serde(rename = "replyUrls", default, skip_serializing_if = "Option::is_none")]
    pub reply_urls: Option<Vec<String>>,
    #[serde(rename = "assertionLifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub assertion_lifetime_min: Option<String>,
    #[serde(rename = "idpInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub idp_initiated_sso: Option<String>,
    #[serde(rename = "spInitiatedSso", default, skip_serializing_if = "Option::is_none")]
    pub sp_initiated_sso: Option<String>,
    #[serde(rename = "ssoConsent", default, skip_serializing_if = "Option::is_none")]
    pub sso_consent: Option<String>,
    #[serde(rename = "signOutUri", default, skip_serializing_if = "Option::is_none")]
    pub sign_out_uri: Option<Vec<String>>,
}

impl WsFederationRelyingParty {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "realms",
            attribute: Some("wsfedRealm"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "replyUrls",
            attribute: Some("wsfedReplyUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "assertionLifetimeMin",
            attribute: Some("wsfedAssertionLifetimeMin"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "idpInitiatedSso",
            attribute: Some("wsfedIdpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "spInitiatedSso",
            attribute: Some("wsfedSpInitiatedSso"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "ssoConsent",
            attribute: Some("wsfedSsoConsent"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "signOutUri",
            attribute: Some("wsfedSignOutUri"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A WS-Trust relying party.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsTrustRelyingParty {
    #[serde(rename = "appliesTo", default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<Vec<String>>,
    #[serde(rename = "jwtScope", default, skip_serializing_if = "Option::is_none")]
    pub jwt_scope: Option<Vec<String>>,
}

impl WsTrustRelyingParty {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("application");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "appliesTo",
            attribute: Some("wstrustAppliesTo"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "jwtScope",
            attribute: Some("wstrustJwtScope"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// A remote policy enforcement point.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPep {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(rename = "certificateSubject", default, skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "notifyUrl", default, skip_serializing_if = "Option::is_none")]
    pub notify_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "registeredAt", default, skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
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
    pub version: Option<String>,
    #[serde(rename = "lastNotify", default, skip_serializing_if = "Option::is_none")]
    pub last_notify: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
}

impl XacmlPep {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("xacmlPep");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "identity",
            attribute: Some("xacmlPepIdentity"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "certificateSubject",
            attribute: Some("xacmlPepCertificateSubject"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "thumbprint",
            attribute: Some("xacmlPepThumbprint"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "authenticated",
            attribute: Some("xacmlPepAuthenticated"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "notifyUrl",
            attribute: Some("xacmlPepNotifyUrl"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "bias",
            attribute: Some("xacmlPepBias"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "resource",
            attribute: Some("xacmlPepResource"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enabled",
            attribute: Some("xacmlPepEnabled"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "registeredAt",
            attribute: Some("xacmlPepRegisteredAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastSeen",
            attribute: Some("xacmlPepLastSeen"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "syncToken",
            attribute: Some("xacmlPepSyncToken"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "policyCount",
            attribute: Some("xacmlPepPolicyCount"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "decisions",
            attribute: Some("xacmlPepDecisions"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "allowed",
            attribute: Some("xacmlPepAllowed"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "refused",
            attribute: Some("xacmlPepRefused"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "undischargeable",
            attribute: Some("xacmlPepUndischargeable"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "version",
            attribute: Some("xacmlPepVersion"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "lastNotify",
            attribute: Some("xacmlPepLastNotify"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// An XACML 3.0 policy or policy set this realm evaluates.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPolicy {
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "combiningAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub combining_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "isRoot", default, skip_serializing_if = "Option::is_none")]
    pub is_root: Option<bool>,
    /// The trust realm whose directory holds the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "orphanedAt", default, skip_serializing_if = "Option::is_none")]
    pub orphaned_at: Option<String>,
}

impl XacmlPolicy {
    /// What the concept is made from: a directory entry or a record.
    pub const MADE_FROM: MadeFrom = MadeFrom::Entry("xacmlPolicy");
    /// Where each field comes from, in the model's order.
    pub const FIELDS: &'static [FieldSource] = &[
        FieldSource {
            name: "identifier",
            attribute: Some("xacmlPolicyId"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "document",
            attribute: Some("xacmlPolicyDocument"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "version",
            attribute: Some("xacmlVersion"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "kind",
            attribute: Some("xacmlKind"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "combiningAlgorithm",
            attribute: Some("xacmlCombiningAlgId"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "enabled",
            attribute: Some("xacmlEnabled"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "isRoot",
            attribute: Some("xacmlIsRoot"),
            on: None,
            key: None,
            transform: Some("first"),
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "realm",
            attribute: None,
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: true,
            embedded: false,
        },
        FieldSource {
            name: "description",
            attribute: Some("description"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "application",
            attribute: Some("xacmlApplication"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
        FieldSource {
            name: "orphanedAt",
            attribute: Some("xacmlOrphanedAt"),
            on: None,
            key: None,
            transform: None,
            secret: false,
            derived: false,
            embedded: false,
        },
    ];
}

/// Every concept's name, in the model's order.
pub const CONCEPTS: &[&str] = &[
    "Application",
    "AttributePolicy",
    "AttributeSource",
    "AuditEvent",
    "AuthenticationEvent",
    "AuthenticationPolicy",
    "CertificateEnrollment",
    "ClaimProvider",
    "Credential",
    "Device",
    "DirectoryEntry",
    "FederationRelationship",
    "GnapClient",
    "Group",
    "IssuedToken",
    "KerberosService",
    "KerberosTrust",
    "LocalePolicy",
    "OAuthClient",
    "OpenIdFederationEntity",
    "PasskeyPolicy",
    "PasswordPolicy",
    "PersonRecord",
    "PostLoginPolicy",
    "Role",
    "SamlServiceProvider",
    "ScimProvisioningTarget",
    "SecretDestination",
    "ServiceAccount",
    "ServiceAccountPolicy",
    "Session",
    "SharedSignalsReceiver",
    "SignerTrustAnchor",
    "SpiffeRegistration",
    "TrustAnchor",
    "User",
    "VerifiableCredentialPartner",
    "WsFederationRelyingParty",
    "WsTrustRelyingParty",
    "XacmlPep",
    "XacmlPolicy",
];
