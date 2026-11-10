// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Application area of the catalogue (#1390). The protocols stay separate
// concepts on purpose: an OAuth client, a SAML service provider and a
// WS-Federation relying party share an identity and little else, and one
// universal model would be the union of three things nobody means.

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Application",
  entry: "application",
  what: "What an OAuth 2.0 client or OpenID Connect relying party is registered with."
})
model OAuthClient {
  @fromAttr(#{attr: "oauthClientId"})
  clientIds?: string[];

  @fromAttr(#{attr: "oauthClientSecret", secret: true})
  clientSecrets?: string[];

  @fromAttr(#{attr: "oauthRedirectUri"})
  redirectUris?: string[];

  @fromAttr(#{attr: "oauthPostLogoutRedirectUri"})
  postLogoutRedirectUris?: string[];

  @fromAttr(#{attr: "oauthGrantType"})
  grantTypes?: string[];

  @fromAttr(#{attr: "oauthResponseType"})
  responseTypes?: string[];

  @fromAttr(#{attr: "oauthTokenEndpointAuthMethod"})
  tokenEndpointAuthMethods?: string[];

  @fromAttr(#{attr: "oauthIdTokenSignedResponseAlg"})
  idTokenSigningAlgorithm?: string;

  @fromAttr(#{attr: "oauthAudience"})
  `audience`?: string[];

  @fromAttr(#{attr: "oauthClaimsRedirectUri"})
  `claimsRedirectUri`?: string[];

  @fromAttr(#{attr: "oauthFrontchannelLogoutUri"})
  `frontchannelLogoutUri`?: string;

  @fromAttr(#{attr: "oauthFrontchannelLogoutSessionRequired"})
  `frontchannelLogoutSessionRequired`?: string;

  @fromAttr(#{attr: "oauthBackchannelLogoutUri"})
  `backchannelLogoutUri`?: string;

  @fromAttr(#{attr: "oauthBackchannelLogoutSessionRequired"})
  `backchannelLogoutSessionRequired`?: string;

  @fromAttr(#{attr: "oauthAllowedTokenResponseTypes"})
  `allowedTokenResponseTypes`?: string[];

  @fromAttr(#{attr: "oauthGrantTypeObserved"})
  `grantTypeObserved`?: string[];

  @fromAttr(#{attr: "oauthResponseTypeObserved"})
  `responseTypeObserved`?: string[];

  @fromAttr(#{attr: "oauthScope"})
  `scope`?: string[];

  @fromAttr(#{attr: "oauthAllowedScope"})
  `allowedScope`?: string[];

  @fromAttr(#{attr: "oauthPermissionBaseUri"})
  `permissionBaseUri`?: string;

  @fromAttr(#{attr: "oauthPermission"})
  `permission`?: string[];

  @fromAttr(#{attr: "oauthRoleGatedPermission"})
  `roleGatedPermission`?: string[];

  @fromAttr(#{attr: "oauthResourceMetadata"})
  `resourceMetadata`?: string;

  @fromAttr(#{attr: "oauthResourceMetadataUrl"})
  `resourceMetadataUrl`?: string;

  @fromAttr(#{attr: "oauthDelegatedPermission"})
  `delegatedPermission`?: string[];

  @fromAttr(#{attr: "oauthGlobalConsent"})
  `globalConsent`?: string[];

  @fromAttr(#{attr: "oauthGlobalConsentWithdrawn"})
  `globalConsentWithdrawn`?: string[];

  @fromAttr(#{attr: "oauthNativeSso"})
  `nativeSso`?: string;

  @fromAttr(#{attr: "oauthNativeSsoGroup"})
  `nativeSsoGroup`?: string;

  @fromAttr(#{attr: "oauthBackchannelTokenDeliveryMode"})
  `backchannelTokenDeliveryMode`?: string;

  @fromAttr(#{attr: "oauthBackchannelClientNotificationEndpoint"})
  `backchannelClientNotificationEndpoint`?: string;

  @fromAttr(#{attr: "oauthCommandEndpoint"})
  `commandEndpoint`?: string;

  @fromAttr(#{attr: "oauthBackchannelAuthenticationRequestSigningAlg"})
  `backchannelAuthenticationRequestSigningAlg`?: string;

  @fromAttr(#{attr: "oauthBackchannelUserCodeParameter"})
  `backchannelUserCodeParameter`?: string;

  @fromAttr(#{attr: "oauthSubjectType"})
  `subjectType`?: string;

  @fromAttr(#{attr: "oauthSectorIdentifierUri"})
  `sectorIdentifierUri`?: string;

  @fromAttr(#{attr: "oauthDidClaimWithPairwise"})
  `didClaimWithPairwise`?: string;

  @fromAttr(#{attr: "oauthTokenEndpointAuthSigningAlg"})
  `tokenEndpointAuthSigningAlg`?: string;

  @fromAttr(#{attr: "oauthJwks"})
  `jwks`?: string;

  @fromAttr(#{attr: "oauthJwksUri"})
  `jwksUri`?: string;

  @fromAttr(#{attr: "oauthIntrospectionSignedResponseAlg"})
  `introspectionSignedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthIntrospectionEncryptedResponseAlg"})
  `introspectionEncryptedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthIntrospectionEncryptedResponseEnc"})
  `introspectionEncryptedResponseEnc`?: string;

  @fromAttr(#{attr: "oauthRequestUri"})
  `requestUri`?: string[];

  @fromAttr(#{attr: "oauthRequestObjectSigningAlg"})
  `requestObjectSigningAlg`?: string;

  @fromAttr(#{attr: "oauthRequestObjectEncryptionAlg"})
  `requestObjectEncryptionAlg`?: string;

  @fromAttr(#{attr: "oauthRequestObjectEncryptionEnc"})
  `requestObjectEncryptionEnc`?: string;

  @fromAttr(#{attr: "oauthRequireSignedRequestObject"})
  `requireSignedRequestObject`?: string;

  @fromAttr(#{attr: "oauthRequirePushedAuthorizationRequests"})
  `requirePushedAuthorizationRequests`?: string;

  @fromAttr(#{attr: "oauthHttpSignedRequests"})
  `httpSignedRequests`?: string;

  @fromAttr(#{attr: "oauthAuthorizationDetailsType"})
  `authorizationDetailsType`?: string[];

  @fromAttr(#{attr: "oauthAuthorizationDetailsTypes"})
  `authorizationDetailsTypes`?: string[];

  @fromAttr(#{attr: "oauthStepUpAcrValues"})
  `stepUpAcrValues`?: string;

  @fromAttr(#{attr: "oauthStepUpMaxAge"})
  `stepUpMaxAge`?: string;

  @fromAttr(#{attr: "oauthIdTokenEncryptedResponseAlg"})
  `idTokenEncryptedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthIdTokenEncryptedResponseEnc"})
  `idTokenEncryptedResponseEnc`?: string;

  @fromAttr(#{attr: "oauthUserinfoSignedResponseAlg"})
  `userinfoSignedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthUserinfoEncryptedResponseAlg"})
  `userinfoEncryptedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthUserinfoEncryptedResponseEnc"})
  `userinfoEncryptedResponseEnc`?: string;

  @fromAttr(#{attr: "oauthAuthorizationSignedResponseAlg"})
  `authorizationSignedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthAuthorizationEncryptedResponseAlg"})
  `authorizationEncryptedResponseAlg`?: string;

  @fromAttr(#{attr: "oauthAuthorizationEncryptedResponseEnc"})
  `authorizationEncryptedResponseEnc`?: string;

  @fromAttr(#{attr: "oauthDefaultAcrValues"})
  `defaultAcrValues`?: string;

  @fromAttr(#{attr: "oauthDefaultMaxAge"})
  `defaultMaxAge`?: string;

  @fromAttr(#{attr: "oauthAssertionIssuer"})
  `assertionIssuer`?: string[];

  @fromAttr(#{attr: "oauthAssertionJwks"})
  `assertionJwks`?: string;

  @fromAttr(#{attr: "oauthAssertionCertificate"})
  `assertionCertificate`?: string;

  @fromAttr(#{attr: "oauthAssertionCertificateChain"})
  `assertionCertificateChain`?: string;

  @fromAttr(#{attr: "oauthAssertionPrivateKey", secret: true})
  `assertionPrivateKey`?: string;

  @fromAttr(#{attr: "oauthAssertionKid"})
  `assertionKid`?: string;

  @fromAttr(#{attr: "oauthAssertionExpiresAt"})
  `assertionExpiresAt`?: string;

  @fromAttr(#{attr: "oauthAssertionKeySource"})
  `assertionKeySource`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionIssuer"})
  `samlAssertionIssuer`?: string[];

  @fromAttr(#{attr: "oauthSamlAssertionSigningCertificate"})
  `samlAssertionSigningCertificate`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionCertificate"})
  `samlAssertionCertificate`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionCertificateChain"})
  `samlAssertionCertificateChain`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionPrivateKey", secret: true})
  `samlAssertionPrivateKey`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionThumbprint"})
  `samlAssertionThumbprint`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionExpiresAt"})
  `samlAssertionExpiresAt`?: string;

  @fromAttr(#{attr: "oauthSamlAssertionKeySource"})
  `samlAssertionKeySource`?: string;

  @fromAttr(#{attr: "oauthSoftwareStatementIssuer"})
  `softwareStatementIssuer`?: string[];

  @fromAttr(#{attr: "oauthIssuedSoftwareStatement"})
  `issuedSoftwareStatement`?: string;

  @fromAttr(#{attr: "oauthTlsClientAuthSubjectDn"})
  `tlsClientAuthSubjectDn`?: string;

  @fromAttr(#{attr: "oauthTlsClientAuthSanDns"})
  `tlsClientAuthSanDns`?: string;

  @fromAttr(#{attr: "oauthTlsClientAuthSanUri"})
  `tlsClientAuthSanUri`?: string;

  @fromAttr(#{attr: "oauthTlsClientAuthSanIp"})
  `tlsClientAuthSanIp`?: string;

  @fromAttr(#{attr: "oauthTlsClientAuthSanEmail"})
  `tlsClientAuthSanEmail`?: string;

  @fromAttr(#{attr: "oauthTlsClientCertificateBoundAccessTokens"})
  `tlsClientCertificateBoundAccessTokens`?: string;

  @fromAttr(#{attr: "oauthTlsClientCertificateThumbprint"})
  `tlsClientCertificateThumbprint`?: string;

  @fromAttr(#{attr: "oauthConfidential"})
  `confidential`?: string;

  @fromAttr(#{attr: "oauthAccessTokenTtlS"})
  `accessTokenTtlS`?: string;

  @fromAttr(#{attr: "oauthIdTokenTtlS"})
  `idTokenTtlS`?: string;

  @fromAttr(#{attr: "oauthRefreshTokenTtlS"})
  `refreshTokenTtlS`?: string;

  @fromAttr(#{attr: "oauthRefreshIdleSeconds"})
  `refreshIdleSeconds`?: string;

  @fromAttr(#{attr: "oauthClaimsAccessToken"})
  `claimsAccessToken`?: string;

  @fromAttr(#{attr: "oauthClaimsIdToken"})
  `claimsIdToken`?: string;

  @fromAttr(#{attr: "oauthClaimsUserinfo"})
  `claimsUserinfo`?: string;

  @fromAttr(#{attr: "oauthClaimAttributesAccessToken"})
  `claimAttributesAccessToken`?: string;

  @fromAttr(#{attr: "oauthClaimAttributesIdToken"})
  `claimAttributesIdToken`?: string;

  @fromAttr(#{attr: "oauthClaimAttributesUserinfo"})
  `claimAttributesUserinfo`?: string;

  @fromAttr(#{attr: "oauthClaimsCombineAccessToken"})
  `claimsCombineAccessToken`?: string;

  @fromAttr(#{attr: "oauthClaimsCombineIdToken"})
  `claimsCombineIdToken`?: string;

  @fromAttr(#{attr: "oauthClaimsCombineUserinfo"})
  `claimsCombineUserinfo`?: string;

  @fromAttr(#{attr: "oauthAccessTokenClaim"})
  `accessTokenClaim`?: string[];

  @fromAttr(#{attr: "oauthPermissionClaims"})
  `permissionClaims`?: string;

  @fromAttr(#{attr: "oauthAccessTokenClaimsCombine"})
  `accessTokenClaimsCombine`?: string;

  @fromAttr(#{attr: "oauthRevokeRefreshOnLogout"})
  `revokeRefreshOnLogout`?: string;

  @fromAttr(#{attr: "oauthThirdPartyInitiatedLogin"})
  `thirdPartyInitiatedLogin`?: string;

  @fromAttr(#{attr: "oauthSpInitiatedSso"})
  `spInitiatedSso`?: string;

  @fromAttr(#{attr: "oauthInitiateLoginUri"})
  `initiateLoginUri`?: string;

  @fromAttr(#{attr: "oauthLogoUri"})
  `logoUri`?: string;

  @fromAttr(#{attr: "oauthPolicyUri"})
  `policyUri`?: string;

  @fromAttr(#{attr: "oauthTosUri"})
  `tosUri`?: string;

  @fromAttr(#{attr: "oauthTokenExchangeRefreshToken"})
  `tokenExchangeRefreshToken`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "What a SAML service provider is registered with."
})
model SamlServiceProvider {
  @fromAttr(#{attr: "samlEntityId"})
  entityIds?: string[];

  @fromAttr(#{attr: "samlAcsEndpoint"})
  assertionConsumerServices?: string[];

  @fromAttr(#{attr: "samlAssertionConsumerService"})
  `assertionConsumerService`?: string[];

  @fromAttr(#{attr: "samlSingleLogoutService"})
  `singleLogoutService`?: string[];

  @fromAttr(#{attr: "samlNameIdFormat"})
  `nameIdFormat`?: string[];

  @fromAttr(#{attr: "samlResponseBinding"})
  `responseBinding`?: string[];

  @fromAttr(#{attr: "samlSigningCertificate"})
  `signingCertificate`?: string[];

  @fromAttr(#{attr: "samlObservedSigningCertificate"})
  `observedSigningCertificate`?: string;

  @fromAttr(#{attr: "samlAuthnRequestVerification"})
  `authnRequestVerification`?: string;

  @fromAttr(#{attr: "samlSpMetadataUrl"})
  `spMetadataUrl`?: string;

  @fromAttr(#{attr: "samlSpMetadata"})
  `spMetadata`?: string;

  @fromAttr(#{attr: "samlEncryptionCertificate"})
  `encryptionCertificate`?: string;

  @fromAttr(#{attr: "samlSloEndpoint"})
  `sloEndpoint`?: string[];

  @fromAttr(#{attr: "samlSpNameIdFormat"})
  `spNameIdFormat`?: string[];

  @fromAttr(#{attr: "samlSpAuthnRequestsSigned"})
  `spAuthnRequestsSigned`?: string;

  @fromAttr(#{attr: "samlSpWantAssertionsSigned"})
  `spWantAssertionsSigned`?: string;

  @fromAttr(#{attr: "samlSpWantAssertionsEncrypted"})
  `spWantAssertionsEncrypted`?: string;

  @fromAttr(#{attr: "samlSpMetadataValidUntil"})
  `spMetadataValidUntil`?: string;

  @fromAttr(#{attr: "samlSpMetadataCacheDuration"})
  `spMetadataCacheDuration`?: string;

  @fromAttr(#{attr: "samlSpMetadataConsumedAt"})
  `spMetadataConsumedAt`?: string;

  @fromAttr(#{attr: "samlSpMetadataSignature"})
  `spMetadataSignature`?: string;

  @fromAttr(#{attr: "samlSpMetadataSigningCertificate"})
  `spMetadataSigningCertificate`?: string;

  @fromAttr(#{attr: "saml2EncryptAssertion"})
  `f2EncryptAssertion`?: string;

  @fromAttr(#{attr: "saml2EncryptionAlgorithm"})
  `f2EncryptionAlgorithm`?: string;

  @fromAttr(#{attr: "saml2KeyTransportAlgorithm"})
  `f2KeyTransportAlgorithm`?: string;

  @fromAttr(#{attr: "saml2EncryptLogoutNameId"})
  `f2EncryptLogoutNameId`?: string;

  @fromAttr(#{attr: "saml2CustomAttributes"})
  `f2CustomAttributes`?: string;

  @fromAttr(#{attr: "saml11CustomAttributes"})
  `f11CustomAttributes`?: string;

  @fromAttr(#{attr: "saml2ClaimAttributes"})
  `f2ClaimAttributes`?: string;

  @fromAttr(#{attr: "saml11ClaimAttributes"})
  `f11ClaimAttributes`?: string;

  @fromAttr(#{attr: "saml2ClaimsCombine"})
  `f2ClaimsCombine`?: string;

  @fromAttr(#{attr: "saml11ClaimsCombine"})
  `f11ClaimsCombine`?: string;

  @fromAttr(#{attr: "saml2AssertionLifetimeMin"})
  `f2AssertionLifetimeMin`?: string;

  @fromAttr(#{attr: "saml2SignAssertion"})
  `f2SignAssertion`?: string;

  @fromAttr(#{attr: "saml2SignResponse"})
  `f2SignResponse`?: string;

  @fromAttr(#{attr: "saml2NameIdFormat"})
  `f2NameIdFormat`?: string;

  @fromAttr(#{attr: "saml2ArtifactTtlS"})
  `f2ArtifactTtlS`?: string;

  @fromAttr(#{attr: "saml11AssertionLifetimeMin"})
  `f11AssertionLifetimeMin`?: string;

  @fromAttr(#{attr: "saml11SignAssertion"})
  `f11SignAssertion`?: string;

  @fromAttr(#{attr: "saml11SignResponse"})
  `f11SignResponse`?: string;

  @fromAttr(#{attr: "saml11NameIdFormat"})
  `f11NameIdFormat`?: string;

  @fromAttr(#{attr: "saml11ArtifactTtlS"})
  `f11ArtifactTtlS`?: string;

  @fromAttr(#{attr: "saml2IdpInitiatedSso"})
  `f2IdpInitiatedSso`?: string;

  @fromAttr(#{attr: "saml2SpInitiatedSso"})
  `f2SpInitiatedSso`?: string;

  @fromAttr(#{attr: "saml11IdpInitiatedSso"})
  `f11IdpInitiatedSso`?: string;

  @fromAttr(#{attr: "saml11SpInitiatedSso"})
  `f11SpInitiatedSso`?: string;

  @fromAttr(#{attr: "samlAuthnRequestSigned"})
  `authnRequestSigned`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "What a WS-Federation relying party is registered with."
})
model WsFederationRelyingParty {
  @fromAttr(#{attr: "wsfedRealm"})
  realms?: string[];

  @fromAttr(#{attr: "wsfedReplyUrl"})
  replyUrls?: string[];

  @fromAttr(#{attr: "wsfedAssertionLifetimeMin"})
  `assertionLifetimeMin`?: string;

  @fromAttr(#{attr: "wsfedIdpInitiatedSso"})
  `idpInitiatedSso`?: string;

  @fromAttr(#{attr: "wsfedSpInitiatedSso"})
  `spInitiatedSso`?: string;

  @fromAttr(#{attr: "wsfedSignOutUri"})
  `signOutUri`?: string[];
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "Something this service issues to or accepts from, in any protocol."
})
@invariant(#{
  id: "application.identifier-is-the-key",
  statement: "The identifier is exactly what the protocol presented; the entry's cn may be a digest of it."
})
@invariant(#{
  id: "application.protocol-identifiers-reach-one-entry",
  statement: "A client id, an entity id and a WS-Federation realm of one application all resolve to this one entry."
})
model Application {
  @fromAttr(#{attr: "appIdentifier"})
  identifier: string;

  @fromAttr(#{attr: "appName"})
  displayName?: string;

  @fromAttr(#{attr: "description"})
  description?: string;

  @fromAttr(#{attr: "appHomePageUrl"})
  homePage?: string;

  @fromAttr(#{attr: "appAllowedProtocol"})
  allowedProtocols?: string[];

  @fromAttr(#{attr: "appRegistered"})
  registered?: boolean;

  @fromAttr(#{attr: "appFirstSeen"})
  firstSeen?: utcDateTime;

  @fromAttr(#{attr: "appLastSeen"})
  lastSeen?: utcDateTime;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @embedded
  oauth?: OAuthClient;

  @embedded
  saml?: SamlServiceProvider;

  @embedded
  wsFederation?: WsFederationRelyingParty;

  @fromAttr(#{attr: "cn"})
  `cn`?: string;

  @fromAttr(#{attr: "appLaunchProtocol"})
  `launchProtocol`?: string;

  @fromAttr(#{attr: "appCorsOrigin"})
  `corsOrigin`?: string[];

  @fromAttr(#{attr: "appKind"})
  `kind`?: string[];

  @fromAttr(#{attr: "appProtocol"})
  `protocol`?: string[];

  @fromAttr(#{attr: "appAuthorizationServer"})
  `authorizationServer`?: string[];

  @fromAttr(#{attr: "appAuthentications"})
  `authentications`?: string;

  @fromAttr(#{attr: "appSessions"})
  `sessions`?: string;

  @fromAttr(#{attr: "appUsers"})
  `users`?: string;

  @fromAttr(#{attr: "appLastSession"})
  `lastSession`?: string;

  @fromAttr(#{attr: "appLastUser"})
  `lastUser`?: string;

  @fromAttr(#{attr: "appRegisteredBy"})
  `registeredBy`?: string;

  @fromAttr(#{attr: "appFederationRegistration"})
  `federationRegistration`?: string;

  @fromAttr(#{attr: "appFederationExpiresAt"})
  `federationExpiresAt`?: string;

  @fromAttr(#{attr: "appFederationTrustAnchor"})
  `federationTrustAnchor`?: string;

  @fromAttr(#{attr: "appRedirectUriObserved"})
  `redirectUriObserved`?: string[];

  @fromAttr(#{attr: "appReturnAddressObserved"})
  `returnAddressObserved`?: string[];

  @fromAttr(#{attr: "appOwner"})
  `owner`?: string[];

  @fromAttr(#{attr: "stsOwnerProtected"})
  `stsOwnerProtected`?: string;

  @fromAttr(#{attr: "authzenAttribute"})
  `authzenAttribute`?: string[];

  @fromAttr(#{attr: "appAuthzenApplication"})
  `authzenApplication`?: string[];

  @fromAttr(#{attr: "appAuthzenCallbackUri"})
  `authzenCallbackUri`?: string[];

  @fromAttr(#{attr: "appSoftwareStatementIssuer"})
  `softwareStatementIssuer`?: string;

  @fromAttr(#{attr: "appSoftwareStatementTrusted"})
  `softwareStatementTrusted`?: string;

  @fromAttr(#{attr: "appSoftwareStatementPublisher"})
  `softwareStatementPublisher`?: string;

  @fromAttr(#{attr: "appRequiredRole"})
  `requiredRole`?: string[];

  @fromAttr(#{attr: "appAllowedToDelegateTo"})
  `allowedToDelegateTo`?: string[];

  @fromAttr(#{attr: "appAllowedToActOnBehalfOf"})
  `allowedToActOnBehalfOf`?: string[];

  @fromAttr(#{attr: "appDelegationSubjectGroup"})
  `delegationSubjectGroup`?: string[];

  @fromAttr(#{attr: "appDelegationSemantics"})
  `delegationSemantics`?: string[];

  @fromAttr(#{attr: "appDefaultDelegationSemantics"})
  `defaultDelegationSemantics`?: string;

  @fromAttr(#{attr: "appNotDelegated"})
  `notDelegated`?: string;

  @fromAttr(#{attr: "appMayAct"})
  `mayAct`?: string;

  @fromAttr(#{attr: "appGroupsClaim"})
  `groupsClaim`?: string;

  @fromAttr(#{attr: "appGroupsClaimName"})
  `groupsClaimName`?: string;

  @fromAttr(#{attr: "appGroupsClaimValue"})
  `groupsClaimValue`?: string;

  @fromAttr(#{attr: "appGroupsClaimFromMemberOf"})
  `groupsClaimFromMemberOf`?: string;

  @fromAttr(#{attr: "appEnrolledCertificate"})
  `enrolledCertificate`?: string[];

  @fromAttr(#{attr: "appEnrolledPrivateKey", secret: true})
  `enrolledPrivateKey`?: string[];

  @fromAttr(#{attr: "appAcmeEabKey", secret: true})
  `acmeEabKey`?: string[];

  @fromAttr(#{attr: "appScepChallenge", secret: true})
  `scepChallenge`?: string[];

  @fromAttr(#{attr: "appCertificateHostName"})
  `certificateHostName`?: string[];

  @fromAttr(#{attr: "appRegistrationJson"})
  `registrationJson`?: string;

  @fromAttr(#{attr: "appRegistrationAccessToken", secret: true})
  `registrationAccessToken`?: string;

  @fromAttr(#{attr: "federationPartnerId"})
  `federationPartnerId`?: string[];

  @fromAttr(#{attr: "ldapBindDn"})
  `ldapBindDn`?: string[];

  @fromAttr(#{attr: "enrollMaxCertificates"})
  `enrollMaxCertificates`?: string;

  @fromAttr(#{attr: "spiffeWorkloadId"})
  `spiffeWorkloadId`?: string[];

  @fromAttr(#{attr: "appFederationRelationship"})
  `federationRelationship`?: string[];

  @fromAttr(#{attr: "appFederationAutoRedirect"})
  `federationAutoRedirect`?: string;

  @fromAttr(#{attr: "appAuthnPolicy"})
  `authnPolicy`?: string;

  @fromAttr(#{attr: "appPasskeyPolicy"})
  `passkeyPolicy`?: string;

  @fromAttr(#{attr: "appLocalePolicy"})
  `localePolicy`?: string;

  @fromAttr(#{attr: "appPasswordPolicy"})
  `passwordPolicy`?: string;

  @fromAttr(#{attr: "appPostLoginPolicy"})
  `postLoginPolicy`?: string;

  @fromAttr(#{attr: "appFgaPolicy"})
  `fgaPolicy`?: string;

  @fromAttr(#{attr: "appFgaEnforced"})
  `fgaEnforced`?: string;

  @fromAttr(#{attr: "umaOwnsResources"})
  `umaOwnsResources`?: string;

  @embedded
  `verifiableCredentialPartner`?: VerifiableCredentialPartner;

  @embedded
  `wsTrustRelyingParty`?: WsTrustRelyingParty;

  @embedded
  `kerberosService`?: KerberosService;

  @embedded
  `gnapClient`?: GnapClient;

  @embedded
  `scimProvisioningTarget`?: ScimProvisioningTarget;

  @embedded
  `certificateEnrollment`?: CertificateEnrollment;

  @embedded
  `secretDestination`?: SecretDestination;

  @embedded
  `sharedSignalsReceiver`?: SharedSignalsReceiver;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "Decentralized identifiers and verifiable credentials."
})
model VerifiableCredentialPartner {
  @fromAttr(#{attr: "vcCredentialClaimAttributes"})
  `credentialClaimAttributes`?: string;

  @fromAttr(#{attr: "oid4vpClientId"})
  `clientId`?: string[];

  @fromAttr(#{attr: "didPublicKeyJwk"})
  `publicKeyJwk`?: string[];

  @fromAttr(#{attr: "didPrivateKeys", secret: true})
  `privateKeys`?: string;

  @fromAttr(#{attr: "didService"})
  `service`?: string[];

  @fromAttr(#{attr: "didAlsoKnownAs"})
  `alsoKnownAs`?: string[];
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "A WS-Trust relying party."
})
model WsTrustRelyingParty {
  @fromAttr(#{attr: "wstrustAppliesTo"})
  `appliesTo`?: string[];

  @fromAttr(#{attr: "wstrustJwtScope"})
  `jwtScope`?: string[];
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "A Kerberos service principal."
})
model KerberosService {
  @fromAttr(#{attr: "krb5ServicePrincipalName"})
  `servicePrincipalName`?: string[];

  @fromAttr(#{attr: "krb5ClaimsPac"})
  `claimsPac`?: string;

  @fromAttr(#{attr: "krb5TrustedForDelegation"})
  `trustedForDelegation`?: string;

  @fromAttr(#{attr: "krb5S4uSelfRealm"})
  `s4uSelfRealm`?: string[];

  @fromAttr(#{attr: "krb5ForeignTgtDelegation"})
  `foreignTgtDelegation`?: string;

  @fromAttr(#{attr: "krb5ServiceKeys", secret: true})
  `serviceKeys`?: string;

  @fromAttr(#{attr: "krb5ServiceKeyInfo"})
  `serviceKeyInfo`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "A GNAP client."
})
model GnapClient {
  @fromAttr(#{attr: "gnapClaimsAccessToken"})
  `claimsAccessToken`?: string;

  @fromAttr(#{attr: "gnapInstanceId"})
  `instanceId`?: string;

  @fromAttr(#{attr: "gnapKey"})
  `key`?: string;

  @fromAttr(#{attr: "gnapKeyIdentity"})
  `keyIdentity`?: string;

  @fromAttr(#{attr: "gnapKeyReference"})
  `keyReference`?: string;

  @fromAttr(#{attr: "gnapKeyProof"})
  `keyProof`?: string;

  @fromAttr(#{attr: "gnapMtlsTrust"})
  `mtlsTrust`?: string;

  @fromAttr(#{attr: "gnapSymmetricKey", secret: true})
  `symmetricKey`?: string;

  @fromAttr(#{attr: "gnapSymmetricAlg"})
  `symmetricAlg`?: string;

  @fromAttr(#{attr: "gnapClassId"})
  `classId`?: string;

  @fromAttr(#{attr: "gnapDisplayUri"})
  `displayUri`?: string;

  @fromAttr(#{attr: "gnapLogoUri"})
  `logoUri`?: string;

  @fromAttr(#{attr: "gnapFinishUri"})
  `finishUri`?: string[];

  @fromAttr(#{attr: "gnapInteractionStartModes"})
  `interactionStartModes`?: string[];

  @fromAttr(#{attr: "gnapAllowedAccess"})
  `allowedAccess`?: string[];

  @fromAttr(#{attr: "gnapBearerTokens"})
  `bearerTokens`?: string;

  @fromAttr(#{attr: "gnapSkipInteraction"})
  `skipInteraction`?: string;

  @fromAttr(#{attr: "gnapAccessTokenFormat"})
  `accessTokenFormat`?: string;

  @fromAttr(#{attr: "gnapAccessTokenLifetimeS"})
  `accessTokenLifetimeS`?: string;

  @fromAttr(#{attr: "gnapResourceServerUri"})
  `resourceServerUri`?: string[];

  @fromAttr(#{attr: "gnapOwnerLookupUri"})
  `ownerLookupUri`?: string;

  @fromAttr(#{attr: "gnapJweKey"})
  `jweKey`?: string;

  @fromAttr(#{attr: "gnapMacaroonKey", secret: true})
  `macaroonKey`?: string;

  @fromAttr(#{attr: "gnapScopedSignals"})
  `scopedSignals`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "Where people are provisioned by SCIM."
})
model ScimProvisioningTarget {
  @fromAttr(#{attr: "scimClientId"})
  `clientId`?: string[];

  @fromAttr(#{attr: "scimClientBaseUrl"})
  `clientBaseUrl`?: string;

  @fromAttr(#{attr: "scimClientEnabled"})
  `clientEnabled`?: string;

  @fromAttr(#{attr: "scimClientAuthMethod"})
  `clientAuthMethod`?: string;

  @fromAttr(#{attr: "scimClientUsername"})
  `clientUsername`?: string;

  @fromAttr(#{attr: "scimClientPassword", secret: true})
  `clientPassword`?: string;

  @fromAttr(#{attr: "scimClientTokenEndpoint"})
  `clientTokenEndpoint`?: string;

  @fromAttr(#{attr: "scimClientOAuthClientId"})
  `clientOAuthClientId`?: string;

  @fromAttr(#{attr: "scimClientOAuthClientSecret", secret: true})
  `clientOAuthClientSecret`?: string;

  @fromAttr(#{attr: "scimClientOAuthClientAuth"})
  `clientOAuthClientAuth`?: string;

  @fromAttr(#{attr: "scimClientOAuthScope"})
  `clientOAuthScope`?: string;

  @fromAttr(#{attr: "scimClientOAuthResource"})
  `clientOAuthResource`?: string;

  @fromAttr(#{attr: "scimClientTlsSource"})
  `clientTlsSource`?: string;

  @fromAttr(#{attr: "scimClientTlsCertificate"})
  `clientTlsCertificate`?: string;

  @fromAttr(#{attr: "scimClientTlsPrivateKey", secret: true})
  `clientTlsPrivateKey`?: string;

  @fromAttr(#{attr: "scimClientCaCertificates"})
  `clientCaCertificates`?: string;

  @fromAttr(#{attr: "scimClientScopeMode"})
  `clientScopeMode`?: string;

  @fromAttr(#{attr: "scimClientScopeGroups"})
  `clientScopeGroups`?: string[];

  @fromAttr(#{attr: "scimClientScopeFilter"})
  `clientScopeFilter`?: string;

  @fromAttr(#{attr: "scimClientGroupMode"})
  `clientGroupMode`?: string;

  @fromAttr(#{attr: "scimClientGroups"})
  `clientGroups`?: string[];

  @fromAttr(#{attr: "scimClientDeprovision"})
  `clientDeprovision`?: string;

  @fromAttr(#{attr: "scimClientReconcileMinutes"})
  `clientReconcileMinutes`?: string;

  @fromAttr(#{attr: "scimClientJurisdiction"})
  `clientJurisdiction`?: string;

  @fromAttr(#{attr: "scimClientCells"})
  `clientCells`?: string[];

  @fromAttr(#{attr: "scimClientMaxRequestsPerSecond"})
  `clientMaxRequestsPerSecond`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "Certificate enrollment by EST, ACME or SCEP."
})
model CertificateEnrollment {
  @fromAttr(#{attr: "acmeAllowedProfiles"})
  `allowedProfiles`?: string[];

  @fromAttr(#{attr: "acmeDefaultProfile"})
  `defaultProfile`?: string;

  @fromAttr(#{attr: "acmeCertificateLifetimeDays"})
  `certificateLifetimeDays`?: string;

  @fromAttr(#{attr: "estAllowedProfiles"})
  `allowedProfiles2`?: string[];

  @fromAttr(#{attr: "estDefaultProfile"})
  `defaultProfile2`?: string;

  @fromAttr(#{attr: "estCertificateLifetimeDays"})
  `certificateLifetimeDays2`?: string;

  @fromAttr(#{attr: "scepAllowedProfiles"})
  `allowedProfiles3`?: string[];

  @fromAttr(#{attr: "scepDefaultProfile"})
  `defaultProfile3`?: string;

  @fromAttr(#{attr: "scepCertificateLifetimeDays"})
  `certificateLifetimeDays3`?: string;

  @fromAttr(#{attr: "estBasicAuthentication"})
  `basicAuthentication`?: string;

  @fromAttr(#{attr: "estCertificateAuthentication"})
  `certificateAuthentication`?: string;

  @fromAttr(#{attr: "estServerKeyGeneration"})
  `serverKeyGeneration`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "Where a rotated password is pushed."
})
model SecretDestination {
  @fromAttr(#{attr: "secretDestProvider"})
  `destProvider`?: string;

  @fromAttr(#{attr: "secretDestPayload"})
  `destPayload`?: string;

  @fromAttr(#{attr: "secretDestRegion"})
  `destRegion`?: string;

  @fromAttr(#{attr: "secretDestProject"})
  `destProject`?: string;

  @fromAttr(#{attr: "secretDestEndpoint"})
  `destEndpoint`?: string;

  @fromAttr(#{attr: "secretDestMount"})
  `destMount`?: string;

  @fromAttr(#{attr: "secretDestField"})
  `destField`?: string;

  @fromAttr(#{attr: "secretDestDirectory"})
  `destDirectory`?: string;

  @fromAttr(#{attr: "secretDestCaCertificates"})
  `destCaCertificates`?: string;

  @fromAttr(#{attr: "secretDestCredential", secret: true})
  `destCredential`?: string;
}

@domain(#{
  area: "Application",
  entry: "application",
  what: "A Shared Signals receiver or transmitter partner."
})
model SharedSignalsReceiver {
  @fromAttr(#{attr: "ssfReceiverId"})
  `receiverId`?: string[];

  @fromAttr(#{attr: "ssfDeliveryEndpoint"})
  `deliveryEndpoint`?: string[];

  @fromAttr(#{attr: "ssfAllowedEvents"})
  `allowedEvents`?: string[];

  @fromAttr(#{attr: "ssfCaepIncludeReasons"})
  `caepIncludeReasons`?: string;

  @fromAttr(#{attr: "ssfCaepReasonLanguage"})
  `caepReasonLanguage`?: string;

  @fromAttr(#{attr: "ssfCaepOmitEventTimestamp"})
  `caepOmitEventTimestamp`?: string;

  @fromAttr(#{attr: "ssfRiscIncludeReasons"})
  `riscIncludeReasons`?: string;

  @fromAttr(#{attr: "ssfRiscReasonLanguage"})
  `riscReasonLanguage`?: string;

  @fromAttr(#{attr: "ssfRiscOmitEventTimestamp"})
  `riscOmitEventTimestamp`?: string;

  @fromAttr(#{attr: "ssfSigningAlgorithm"})
  `signingAlgorithm`?: string;

  @fromAttr(#{attr: "ssfMinVerificationInterval"})
  `minVerificationInterval`?: string;

  @fromAttr(#{attr: "ssfInactivityTimeoutS"})
  `inactivityTimeoutS`?: string;

  @fromAttr(#{attr: "ssfInactivityAction"})
  `inactivityAction`?: string;

  @fromAttr(#{attr: "ssfVerificationEveryS"})
  `verificationEveryS`?: string;

  @fromAttr(#{attr: "ssfStreamStatusOnCreate"})
  `streamStatusOnCreate`?: string;

  @fromAttr(#{attr: "ssfMaxStreams"})
  `maxStreams`?: string;

  @fromAttr(#{attr: "ssfMaxSubjectsPerStream"})
  `maxSubjectsPerStream`?: string;

  @fromAttr(#{attr: "ssfMaxQueuedEvents"})
  `maxQueuedEvents`?: string;

  @fromAttr(#{attr: "ssfPollMaxEvents"})
  `pollMaxEvents`?: string;

  @fromAttr(#{attr: "ssfDeadLetterMaxPerStream"})
  `deadLetterMaxPerStream`?: string;

  @fromAttr(#{attr: "ssfPushTimeoutMs"})
  `pushTimeoutMs`?: string;

  @fromAttr(#{attr: "ssfPushRetries"})
  `pushRetries`?: string;

  @fromAttr(#{attr: "ssfPushRetryDelayMs"})
  `pushRetryDelayMs`?: string;
}
