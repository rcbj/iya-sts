// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Federation area of the catalogue (#1390).

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Federation",
  entry: "federationRelationship",
  what: "An agreement with one partner, in either direction and one protocol."
})
@invariant(#{
  id: "federation.configured-only",
  statement: "This service federates only with a partner somebody configured; it is the one refusal by default."
})
model FederationRelationship {
  @fromAttr(#{attr: "fedId"})
  identifier: string;

  @fromAttr(#{attr: "fedName"})
  name?: string;

  @fromAttr(#{attr: "fedRole"})
  role?: string;

  @fromAttr(#{attr: "fedProtocol"})
  protocol?: string;

  @fromAttr(#{attr: "fedProvider"})
  provider?: string;

  @fromAttr(#{attr: "fedPeer"})
  peer?: string;

  @fromAttr(#{attr: "fedLocalEntityId"})
  localEntityId?: string;

  @fromAttr(#{attr: "fedEnabled"})
  enabled?: boolean;

  @fromAttr(#{attr: "fedClientId"})
  clientId?: string;

  @fromAttr(#{attr: "fedClientSecret", secret: true})
  clientSecret?: string;

  @fromAttr(#{attr: "fedSsoUrl"})
  authorizationUrl?: string;

  @fromAttr(#{attr: "fedTokenUrl"})
  tokenUrl?: string;

  @fromAttr(#{attr: "fedJwksUri"})
  jwksUri?: string;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @fromAttr(#{attr: "cn"})
  `cn`?: string;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "fedUserinfoUrl"})
  `userinfoUrl`?: string;

  @fromAttr(#{attr: "fedEmailsUrl"})
  `emailsUrl`?: string;

  @fromAttr(#{attr: "fedJwks"})
  `jwks`?: string;

  @fromAttr(#{attr: "fedTrustAnchor"})
  `trustAnchor`?: string;

  @fromAttr(#{attr: "fedSigningCertificate"})
  `signingCertificate`?: string;

  @fromAttr(#{attr: "fedResponseMode"})
  `responseMode`?: string;

  @fromAttr(#{attr: "fedAllowedTenants"})
  `allowedTenants`?: string[];

  @fromAttr(#{attr: "fedTeamId"})
  `teamId`?: string;

  @fromAttr(#{attr: "fedKeyId"})
  `keyId`?: string;

  @fromAttr(#{attr: "fedClientSigningKey", secret: true})
  `clientSigningKey`?: string;

  @fromAttr(#{attr: "fedAuthorizeParams"})
  `authorizeParams`?: string[];

  @fromAttr(#{attr: "fedTokenAuth"})
  `tokenAuth`?: string;

  @fromAttr(#{attr: "fedScope"})
  `scope`?: string;

  @fromAttr(#{attr: "fedResponseType"})
  `responseType`?: string;

  @fromAttr(#{attr: "fedIdTokenSignedResponseAlg"})
  `idTokenSignedResponseAlg`?: string;

  @fromAttr(#{attr: "fedUserinfoSignedResponseAlg"})
  `userinfoSignedResponseAlg`?: string;

  @fromAttr(#{attr: "fedRefreshTokens"})
  `refreshTokens`?: string;

  @fromAttr(#{attr: "fedRefreshEverySeconds"})
  `refreshEverySeconds`?: string;

  @fromAttr(#{attr: "fedRegister"})
  `register`?: string;

  @fromAttr(#{attr: "fedRegisteredIssuer"})
  `registeredIssuer`?: string;

  @fromAttr(#{attr: "fedRequestObject"})
  `requestObject`?: string;

  @fromAttr(#{attr: "fedRequestObjectSigningAlg"})
  `requestObjectSigningAlg`?: string;

  @fromAttr(#{attr: "fedWebFinger"})
  `webFinger`?: string;

  @fromAttr(#{attr: "fedDiscovery"})
  `discovery`?: string;

  @fromAttr(#{attr: "fedFapi"})
  `fapi`?: string;

  @fromAttr(#{attr: "fedInitiateLogin"})
  `initiateLogin`?: string;

  @fromAttr(#{attr: "fedBinding"})
  `binding`?: string;

  @fromAttr(#{attr: "fedSignRequest"})
  `signRequest`?: string;

  @fromAttr(#{attr: "fedUsernameSource"})
  `usernameSource`?: string;

  @fromAttr(#{attr: "fedSubjectClaim"})
  `subjectClaim`?: string;

  @fromAttr(#{attr: "fedAttributeMap"})
  `attributeMap`?: string[];

  @fromAttr(#{attr: "fedAutocreateUsers"})
  `autocreateUsers`?: string;

  @fromAttr(#{attr: "fedUpdateUserAttributes"})
  `updateUserAttributes`?: string;

  @fromAttr(#{attr: "fedProvisionGroups"})
  `provisionGroups`?: string;

  @fromAttr(#{attr: "fedProvisionCap"})
  `provisionCap`?: string;

  @fromAttr(#{attr: "fedProvisionIdleMinutes"})
  `provisionIdleMinutes`?: string;

  @fromAttr(#{attr: "fedSubjectPolicy"})
  `subjectPolicy`?: string;

  @fromAttr(#{attr: "fedSubjectGroup"})
  `subjectGroup`?: string[];

  @fromAttr(#{attr: "fedSubjectDomain"})
  `subjectDomain`?: string[];

  @fromAttr(#{attr: "fedHomeRealmDomain"})
  `homeRealmDomain`?: string[];

  @fromAttr(#{attr: "fedSubjectPattern"})
  `subjectPattern`?: string;

  @fromAttr(#{attr: "fedMayAssertAdministrators"})
  `mayAssertAdministrators`?: string;

  @fromAttr(#{attr: "fedSignalEmailMatch"})
  `signalEmailMatch`?: string;

  @fromAttr(#{attr: "fedSignalsEnabled"})
  `signalsEnabled`?: string;

  @fromAttr(#{attr: "fedSignalsIssuer"})
  `signalsIssuer`?: string;

  @fromAttr(#{attr: "fedSignalsDelivery"})
  `signalsDelivery`?: string;

  @fromAttr(#{attr: "fedSignalsEvents"})
  `signalsEvents`?: string[];

  @fromAttr(#{attr: "fedSignalsTokenUrl"})
  `signalsTokenUrl`?: string;

  @fromAttr(#{attr: "fedSignalsClientId"})
  `signalsClientId`?: string;

  @fromAttr(#{attr: "fedSignalsClientSecret", secret: true})
  `signalsClientSecret`?: string;

  @fromAttr(#{attr: "fedSignalsScope"})
  `signalsScope`?: string;

  @fromAttr(#{attr: "fedSignalsBearer", secret: true})
  `signalsBearer`?: string;

  @fromAttr(#{attr: "fedSloUrl"})
  `sloUrl`?: string;

  @fromAttr(#{attr: "fedSloBinding"})
  `sloBinding`?: string;

  @fromAttr(#{attr: "fedEndSessionUrl"})
  `endSessionUrl`?: string;

  @fromAttr(#{attr: "fedAcceptSignout"})
  `acceptSignout`?: string;

  @fromAttr(#{attr: "fedRequireSignedLogout"})
  `requireSignedLogout`?: string;

  @fromAttr(#{attr: "fedEncryptionKeyType"})
  `encryptionKeyType`?: string;

  @fromAttr(#{attr: "fedKeyManagementAlgorithm"})
  `keyManagementAlgorithm`?: string;

  @fromAttr(#{attr: "fedContentEncryptionAlgorithm"})
  `contentEncryptionAlgorithm`?: string;

  @fromAttr(#{attr: "fedAllowUnencrypted"})
  `allowUnencrypted`?: string;

  @fromAttr(#{attr: "fedEncryptionKey", secret: true})
  `encryptionKey`?: string[];

  @fromAttr(#{attr: "fedClientCertificate", secret: true})
  `clientCertificate`?: string;

  @fromAttr(#{attr: "fedAllowUnsolicited"})
  `allowUnsolicited`?: string;

  @fromAttr(#{attr: "fedApplication"})
  `application`?: string;

  @fromAttr(#{attr: "fedAuthnMechanism"})
  `authnMechanism`?: string;

  @fromAttr(#{attr: "fedAuthnRelationship"})
  `authnRelationship`?: string;

  @fromAttr(#{attr: "fedRelease"})
  `release`?: string[];

  @fromAttr(#{attr: "fedFirstSeen"})
  `firstSeen`?: string;

  @fromAttr(#{attr: "fedLastSeen"})
  `lastSeen`?: string;

  @fromAttr(#{attr: "fedAuthentications"})
  `authentications`?: string;

  @fromAttr(#{attr: "fedUsers"})
  `users`?: string;

  @fromAttr(#{attr: "fedLastUser"})
  `lastUser`?: string;

  @fromAttr(#{attr: "fedApplicationUse"})
  `applicationUse`?: string[];

  @fromAttr(#{attr: "fedLastError"})
  `lastError`?: string;

  @fromAttr(#{attr: "fedLastErrorAt"})
  `lastErrorAt`?: string;
}
