// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Identity area of the catalogue (#1390). A credential is not a field of
// a person here: it is a concept of its own, reached deliberately, so that
// passing a User around cannot carry one.

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Identity",
  entry: "person",
  what: "A person this service authenticates, as every protocol projects them."
})
@invariant(#{
  id: "user.subject-outlives-the-username",
  statement: "The subject comes from entryUUID, so renaming a person does not make them somebody else."
})
@invariant(#{
  id: "user.no-credential",
  statement: "A User carries no password, key, token or recovery code."
})
model User {
  @fromAttr(#{attr: "entryUUID", on: "operational"})
  entryUuid: string;

  @fromAttr(#{attr: "uid", transform: "first"})
  username: string;

  @fromAttr(#{attr: "displayName", transform: "first"})
  displayName?: string;

  @fromAttr(#{attr: "givenName", transform: "first"})
  givenName?: string;

  @fromAttr(#{attr: "sn", transform: "first"})
  familyName?: string;

  @fromAttr(#{attr: "mail", transform: "first"})
  email?: string;

  @fromAttr(#{attr: "preferredLanguage", transform: "first"})
  preferredLanguage?: string;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @fromAttr(#{attr: "cn"})
  `cn`?: string[];

  @fromAttr(#{attr: "title"})
  `title`?: string[];

  @fromAttr(#{attr: "employeeType"})
  `employeeType`?: string[];

  @fromAttr(#{attr: "telephoneNumber"})
  `telephoneNumber`?: string[];

  @fromAttr(#{attr: "mobile"})
  `mobile`?: string[];

  @fromAttr(#{attr: "street"})
  `street`?: string[];

  @fromAttr(#{attr: "l"})
  `l`?: string[];

  @fromAttr(#{attr: "st"})
  `st`?: string[];

  @fromAttr(#{attr: "postalCode"})
  `postalCode`?: string[];

  @fromAttr(#{attr: "c"})
  `c`?: string;

  @fromAttr(#{attr: "postalAddress"})
  `postalAddress`?: string[];

  @fromAttr(#{attr: "o"})
  `o`?: string[];

  @fromAttr(#{attr: "ou"})
  `ou`?: string[];

  @fromAttr(#{attr: "departmentNumber"})
  `departmentNumber`?: string[];

  @fromAttr(#{attr: "employeeNumber"})
  `employeeNumber`?: string;

  @fromAttr(#{attr: "labeledURI"})
  `labeledURI`?: string[];

  @fromAttr(#{attr: "manager"})
  `manager`?: string[];

  @fromAttr(#{attr: "schacDateOfBirth"})
  `schacDateOfBirth`?: string;

  @fromAttr(#{attr: "schacCountryOfCitizenship"})
  `schacCountryOfCitizenship`?: string[];

  @fromAttr(#{attr: "schacPersonalTitle"})
  `schacPersonalTitle`?: string[];

  @fromAttr(#{attr: "salutation"})
  `salutation`?: string[];

  @fromAttr(#{attr: "birthFamilyName"})
  `birthFamilyName`?: string[];

  @fromAttr(#{attr: "birthGivenName"})
  `birthGivenName`?: string[];

  @fromAttr(#{attr: "birthMiddleName"})
  `birthMiddleName`?: string[];

  @fromAttr(#{attr: "alsoKnownAs"})
  `alsoKnownAs`?: string[];

  @fromAttr(#{attr: "placeOfBirthCountry"})
  `placeOfBirthCountry`?: string;

  @fromAttr(#{attr: "placeOfBirthRegion"})
  `placeOfBirthRegion`?: string;

  @fromAttr(#{attr: "placeOfBirthLocality"})
  `placeOfBirthLocality`?: string;

  @fromAttr(#{attr: "schacGender"})
  `schacGender`?: string;

  @fromAttr(#{attr: "middleName"})
  `middleName`?: string;

  @fromAttr(#{attr: "timeZone"})
  `timeZone`?: string;

  @fromAttr(#{attr: "pictureUrl"})
  `pictureUrl`?: string;

  @fromAttr(#{attr: "profileUrl"})
  `profileUrl`?: string;

  @fromAttr(#{attr: "scimExternalId"})
  `scimExternalId`?: string;

  @fromAttr(#{attr: "userPrincipalName"})
  `userPrincipalName`?: string;
}

@domain(#{
  area: "Identity",
  entry: "person",
  what: "Everything a person proves themselves with: the concept a User deliberately is not."
})
@invariant(#{
  id: "credential.reached-deliberately",
  statement: "A credential is read only by the code that verifies or manages one, and is never a field of a User."
})
model Credential {
  @fromAttr(#{attr: "userPassword", transform: "first", secret: true})
  passwordHash?: string;

  @fromAttr(#{attr: "stsTotpCredential", secret: true})
  authenticatorApp?: string;

  @fromAttr(#{attr: "stsWebauthnCredential"})
  passkeys?: string[];

  @fromAttr(#{attr: "stsBackupCodes", transform: "first", secret: true})
  recoveryCodes?: string;

  @fromAttr(#{attr: "stsAppPassword", secret: true})
  appPasswords?: string;

  @fromAttr(#{attr: "pwdChangedTime", transform: "first"})
  passwordChanged?: string;

  @fromAttr(#{attr: "pwdReset", transform: "first"})
  passwordMustChange?: boolean;

  @fromAttr(#{attr: "pwdAccountLockedTime", transform: "first"})
  lockedSince?: string;

  @fromAttr(#{attr: "userCertificate"})
  `userCertificate`?: string[];

  @fromAttr(#{attr: "stsKrb5KeyInfo"})
  `krb5KeyInfo`?: string;

  @fromAttr(#{attr: "hobaPublicKey"})
  `hobaPublicKey`?: string[];

  @fromAttr(#{attr: "stsActivationExpires"})
  `activationExpires`?: string;

  @fromAttr(#{attr: "stsPasswordResetExpires"})
  `passwordResetExpires`?: string;

  @fromAttr(#{attr: "pwdHistory", secret: true})
  `pwdHistory`?: string[];

  @fromAttr(#{attr: "stsActivationToken", secret: true})
  `activationToken`?: string;

  @fromAttr(#{attr: "stsProfilePhoto", secret: true})
  `profilePhoto`?: string;

  @fromAttr(#{attr: "stsPasswordResetToken", secret: true})
  `passwordResetToken`?: string;

  @fromAttr(#{attr: "stsKrb5Keys", secret: true})
  `krb5Keys`?: string;

  @fromAttr(#{attr: "stsSelfIssuedSubject", secret: true})
  `selfIssuedSubject`?: string[];

  @fromAttr(#{attr: "stsPublishedDid", secret: true})
  `publishedDid`?: string[];

  @fromAttr(#{attr: "stsCibaUserCode", secret: true})
  `cibaUserCode`?: string;

  @fromAttr(#{attr: "stsAndroidAttestedCredential"})
  `androidAttestedCredential`?: string[];

  @fromAttr(#{attr: "stsWebauthnUserHandle"})
  `webauthnUserHandle`?: string;

  @fromAttr(#{attr: "stsWebauthnPqcUserHandle"})
  `webauthnPqcUserHandle`?: string;

  @fromAttr(#{attr: "stsMailVerifyToken", secret: true})
  `mailVerifyToken`?: string;

  @fromAttr(#{attr: "stsMailVerifyExpires"})
  `mailVerifyExpires`?: string;

  @fromAttr(#{attr: "stsMailVerifyAddress"})
  `mailVerifyAddress`?: string;

  @fromAttr(#{attr: "stsPseudonym"})
  `pseudonym`?: string[];

  @fromAttr(#{attr: "stsPseudonymVerifyToken", secret: true})
  `pseudonymVerifyToken`?: string;

  @fromAttr(#{attr: "stsPseudonymVerifyExpires"})
  `pseudonymVerifyExpires`?: string;

  @fromAttr(#{attr: "stsPseudonymVerifyAddress"})
  `pseudonymVerifyAddress`?: string;

  @fromAttr(#{attr: "stsAssertionIssuer"})
  `assertionIssuer`?: string[];

  @fromAttr(#{attr: "stsAssertionKeyPair"})
  `assertionKeyPair`?: string[];

  @fromAttr(#{attr: "stsAssertionPrivateKey", secret: true})
  `assertionPrivateKey`?: string[];

  @fromAttr(#{attr: "stsSamlAssertionIssuer"})
  `samlAssertionIssuer`?: string[];

  @fromAttr(#{attr: "stsSamlAssertionKeyPair"})
  `samlAssertionKeyPair`?: string[];

  @fromAttr(#{attr: "stsSamlAssertionPrivateKey", secret: true})
  `samlAssertionPrivateKey`?: string[];

  @fromAttr(#{attr: "stsEnrolledCertificate"})
  `enrolledCertificate`?: string[];

  @fromAttr(#{attr: "stsEnrolledPrivateKey", secret: true})
  `enrolledPrivateKey`?: string[];

  @fromAttr(#{attr: "stsAcmeEabKey", secret: true})
  `acmeEabKey`?: string[];

  @fromAttr(#{attr: "stsScepChallenge", secret: true})
  `scepChallenge`?: string[];

  @fromAttr(#{attr: "stsCertificateHostName"})
  `certificateHostName`?: string[];

  @fromAttr(#{attr: "stsIdaVerification", secret: true})
  `idaVerification`?: string;

  @fromAttr(#{attr: "stsClaimSourceTokens", secret: true})
  `claimSourceTokens`?: string;
}

@domain(#{
  area: "Identity",
  entry: "group",
  what: "A set of people, and the policies that apply to its members. A group grants nothing by being a group."
})
@invariant(#{
  id: "group.grants-nothing",
  statement: "Being a member of a group grants nothing; a role or a policy naming the group does."
})
model Group {
  @fromAttr(#{attr: "cn", transform: "first"})
  name: string;

  @fromAttr(#{attr: "description", transform: "first"})
  description?: string;

  @fromAttr(#{attr: "member"})
  members?: string[];

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @fromAttr(#{attr: "uniqueMember"})
  `uniqueMember`?: string[];

  @fromAttr(#{attr: "memberUid"})
  `memberUid`?: string[];

  @fromAttr(#{attr: "stsPasskeyPolicy"})
  `stsPasskeyPolicy`?: string;

  @fromAttr(#{attr: "stsLocalePolicy"})
  `stsLocalePolicy`?: string;

  @fromAttr(#{attr: "stsPasswordPolicy"})
  `stsPasswordPolicy`?: string;

  @fromAttr(#{attr: "stsAuthnPolicy"})
  `stsAuthnPolicy`?: string;

  @fromAttr(#{attr: "stsPostLoginPolicy"})
  `stsPostLoginPolicy`?: string;

  @fromAttr(#{attr: "stsAttributePolicy"})
  `stsAttributePolicy`?: string;

  @fromAttr(#{attr: "federationRelationship"})
  `federationRelationship`?: string[];

  @fromAttr(#{attr: "mail", transform: "first"})
  email?: string;

  @fromAttr(#{attr: "displayName"})
  displayName?: string;
}

@domain(#{
  area: "Identity",
  entry: "serviceAccount",
  what: "An account a program uses, rotated by this service and owned by a person."
})
@invariant(#{
  id: "service-account.no-second-factor",
  statement: "Nobody is there to answer a second factor, so product mode requiring one of everybody means people."
})
model ServiceAccount {
  @fromAttr(#{attr: "stsServiceAccountOwner"})
  owners?: string[];

  @fromAttr(#{attr: "stsSecretDestination"})
  secretDestination?: string;

  @fromAttr(#{attr: "stsSecretName", transform: "first"})
  secretName?: string;

  @fromAttr(#{attr: "stsRotationFailures", transform: "first"})
  rotationFailures?: integer;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @fromAttr(#{attr: "stsServiceAccount"})
  `serviceAccount`?: boolean;

  @fromAttr(#{attr: "stsPasswordRotatedAt"})
  `passwordRotatedAt`?: string;

  @fromAttr(#{attr: "stsPreviousPassword", secret: true})
  `previousPassword`?: string;

  @fromAttr(#{attr: "stsPreviousPasswordExpires"})
  `previousPasswordExpires`?: string;

  @fromAttr(#{attr: "stsRotationLastError"})
  `rotationLastError`?: string;

  @fromAttr(#{attr: "stsRotationLastAttempt"})
  `rotationLastAttempt`?: string;

  @fromAttr(#{attr: "stsOwnerProtected"})
  `ownerProtected`?: boolean;

  @fromAttr(#{attr: "stsServiceAccountPolicy"})
  `serviceAccountPolicy`?: string;
}

@domain(#{
  area: "Identity",
  entry: "device",
  what: "A device registered in a realm, and what is known about its state."
})
model Device {
  @fromAttr(#{attr: "cn"})
  identifier: string;

  @fromAttr(#{attr: "owner"})
  owner?: string;

  @fromAttr(#{attr: "stsDeviceOwnerKind"})
  ownerKind?: string;

  @fromAttr(#{attr: "description"})
  description?: string;

  @fromAttr(#{attr: "stsDeviceApplication"})
  applications?: string[];

  @fromAttr(#{attr: "stsDeviceCompliance"})
  compliance?: string;

  @fromAttr(#{attr: "stsDeviceStatus"})
  status?: string;

  @fromAttr(#{attr: "stsDeviceRiskLevel"})
  riskLevel?: string;

  @fromAttr(#{attr: "stsDevicePlatform"})
  platform?: string;

  @fromAttr(#{attr: "stsDeviceLastUsed"})
  lastUsed?: string;

  @derived(#{how: "The trust realm whose directory holds the entry."})
  realm: string;

  @fromAttr(#{attr: "stsDeviceKey"})
  `key`?: string[];

  @fromAttr(#{attr: "stsDeviceKeyThumbprint"})
  `keyThumbprint`?: string[];

  @fromAttr(#{attr: "stsDeviceCredentialId"})
  `credentialId`?: string[];

  @fromAttr(#{attr: "stsDeviceAndroidKey"})
  `androidKey`?: string[];

  @fromAttr(#{attr: "stsDeviceAttestation"})
  `attestation`?: string;

  @fromAttr(#{attr: "stsDeviceComplianceChange"})
  `complianceChange`?: string;

  @fromAttr(#{attr: "stsDeviceStatusChange"})
  `statusChange`?: string;

  @fromAttr(#{attr: "stsDeviceRiskChange"})
  `riskChange`?: string;

  @fromAttr(#{attr: "stsDeviceBrowser"})
  `browser`?: string;

  @fromAttr(#{attr: "stsDeviceModel"})
  `model`?: string;

  @fromAttr(#{attr: "stsDeviceOs"})
  `os`?: string;

  @fromAttr(#{attr: "stsDeviceEnrolment"})
  `enrolment`?: string;

  @fromAttr(#{attr: "stsDeviceSecretHash", secret: true})
  `secretHash`?: string;

  @fromAttr(#{attr: "stsDeviceSession"})
  `session`?: string;
}

@domain(#{
  area: "Identity",
  entry: "person",
  what: "What this service keeps about a person beyond their profile and credentials: federation links, delegation, consent and SPIFFE subjects."
})
model PersonRecord {
  @fromAttr(#{attr: "x509subject"})
  `x509subject`?: string[];

  @fromAttr(#{attr: "x509issuer"})
  `x509issuer`?: string[];

  @fromAttr(#{attr: "x509serialNumber"})
  `x509serialNumber`?: string[];

  @fromAttr(#{attr: "x509notBefore"})
  `x509notBefore`?: string[];

  @fromAttr(#{attr: "x509notAfter"})
  `x509notAfter`?: string[];

  @fromAttr(#{attr: "x509fingerprint256"})
  `x509fingerprint256`?: string[];

  @fromAttr(#{attr: "x509svidsIssued"})
  `x509svidsIssued`?: integer;

  @fromAttr(#{attr: "x509firstIssued"})
  `x509firstIssued`?: string;

  @fromAttr(#{attr: "x509lastIssued"})
  `x509lastIssued`?: string;

  @fromAttr(#{attr: "didSubject"})
  `didSubject`?: string[];

  @fromAttr(#{attr: "didMethod"})
  `didMethod`?: string[];

  @fromAttr(#{attr: "spiffeSubject"})
  `spiffeSubject`?: string[];

  @fromAttr(#{attr: "spiffePath"})
  `spiffePath`?: string;

  @fromAttr(#{attr: "spiffeTrustDomain"})
  `spiffeTrustDomain`?: string;

  @fromAttr(#{attr: "spiffeCredentialStatus"})
  `spiffeCredentialStatus`?: string;

  @fromAttr(#{attr: "spiffeCredentialStatusReason"})
  `spiffeCredentialStatusReason`?: string;

  @fromAttr(#{attr: "spiffeRevokedAt"})
  `spiffeRevokedAt`?: string;

  @fromAttr(#{attr: "authnMethod"})
  `authnMethod`?: string[];

  @fromAttr(#{attr: "mfaAuthenticated"})
  `mfaAuthenticated`?: boolean;

  @fromAttr(#{attr: "mfaLastAuthTime"})
  `mfaLastAuthTime`?: string;

  @fromAttr(#{attr: "federationIssuer"})
  `federationIssuer`?: string[];

  @fromAttr(#{attr: "federationLink"})
  `federationLink`?: string[];

  @fromAttr(#{attr: "federationLastSeen"})
  `federationLastSeen`?: string;

  @fromAttr(#{attr: "federationAttribute"})
  `federationAttribute`?: string[];

  @fromAttr(#{attr: "stsProvisionedBy"})
  `provisionedBy`?: string;

  @fromAttr(#{attr: "oauthConsent"})
  `oauthConsent`?: string[];

  @fromAttr(#{attr: "oauthConsentWithdrawn"})
  `oauthConsentWithdrawn`?: string[];

  @fromAttr(#{attr: "oauthConsentApplied"})
  `oauthConsentApplied`?: string[];

  @fromAttr(#{attr: "stsBootstrapAdministrator"})
  `bootstrapAdministrator`?: boolean;

  @fromAttr(#{attr: "stsConsoleClaimedAt"})
  `consoleClaimedAt`?: string;

  @fromAttr(#{attr: "stsMfaRequired"})
  `mfaRequired`?: boolean;

  @fromAttr(#{attr: "stsNotDelegated"})
  `notDelegated`?: boolean;

  @fromAttr(#{attr: "stsMayAct"})
  `mayAct`?: string;

  @fromAttr(#{attr: "stsDelegationSemantics"})
  `delegationSemantics`?: string[];

  @fromAttr(#{attr: "stsDefaultDelegationSemantics"})
  `defaultDelegationSemantics`?: string;

  @fromAttr(#{attr: "stsAuthzenApplication"})
  `authzenApplication`?: string[];

  @fromAttr(#{attr: "stsAuthzenCallbackUri"})
  `authzenCallbackUri`?: string[];

  @fromAttr(#{attr: "stsMailVerified"})
  `mailVerified`?: string;

  @fromAttr(#{attr: "stsAudSub"})
  `audSub`?: string[];
}
