// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The remaining areas of the catalogue (#1390): directory bookkeeping, policies and the registers other concepts refer to.

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Authorization",
  entry: "xacmlPep",
  what: "A remote policy enforcement point."
})
model XacmlPep {
  @fromAttr(#{attr: "xacmlPepIdentity"})
  `identity`?: string;

  @fromAttr(#{attr: "xacmlPepCertificateSubject"})
  `certificateSubject`?: string;

  @fromAttr(#{attr: "xacmlPepThumbprint"})
  `thumbprint`?: string;

  @fromAttr(#{attr: "xacmlPepAuthenticated"})
  `authenticated`?: boolean;

  @fromAttr(#{attr: "xacmlPepNotifyUrl"})
  `notifyUrl`?: string;

  @fromAttr(#{attr: "xacmlPepBias"})
  `bias`?: string;

  @fromAttr(#{attr: "xacmlPepResource"})
  `resource`?: string;

  @fromAttr(#{attr: "xacmlPepEnabled"})
  `enabled`?: boolean;

  @fromAttr(#{attr: "xacmlPepRegisteredAt"})
  `registeredAt`?: string;

  @fromAttr(#{attr: "xacmlPepLastSeen"})
  `lastSeen`?: string;

  @fromAttr(#{attr: "xacmlPepSyncToken"})
  `syncToken`?: string;

  @fromAttr(#{attr: "xacmlPepPolicyCount"})
  `policyCount`?: integer;

  @fromAttr(#{attr: "xacmlPepDecisions"})
  `decisions`?: integer;

  @fromAttr(#{attr: "xacmlPepAllowed"})
  `allowed`?: integer;

  @fromAttr(#{attr: "xacmlPepRefused"})
  `refused`?: integer;

  @fromAttr(#{attr: "xacmlPepUndischargeable"})
  `undischargeable`?: integer;

  @fromAttr(#{attr: "xacmlPepVersion"})
  `version`?: string;

  @fromAttr(#{attr: "xacmlPepLastNotify"})
  `lastNotify`?: string;

  @fromAttr(#{attr: "description"})
  `description`?: string[];
}

@domain(#{
  area: "Identity",
  entry: "spiffe",
  what: "A SPIFFE registration entry."
})
model SpiffeRegistration {
  @fromAttr(#{attr: "spiffeEntryId"})
  `entryId`?: string;

  @fromAttr(#{attr: "cn"})
  `cn`?: string;

  @fromAttr(#{attr: "spiffeId"})
  `id`?: string;

  @fromAttr(#{attr: "spiffeParentId"})
  `parentId`?: string;

  @fromAttr(#{attr: "spiffeSelector"})
  `selector`?: string[];

  @fromAttr(#{attr: "spiffeX509SvidTtl"})
  `x509SvidTtl`?: string;

  @fromAttr(#{attr: "spiffeJwtSvidTtl"})
  `jwtSvidTtl`?: string;

  @fromAttr(#{attr: "spiffeDnsName"})
  `dnsName`?: string[];

  @fromAttr(#{attr: "spiffeFederatesWith"})
  `federatesWith`?: string[];

  @fromAttr(#{attr: "spiffeHint"})
  `hint`?: string;

  @fromAttr(#{attr: "spiffeAdmin"})
  `admin`?: string;

  @fromAttr(#{attr: "spiffeDownstream"})
  `downstream`?: string;

  @fromAttr(#{attr: "spiffeStoreSvid"})
  `storeSvid`?: string;

  @fromAttr(#{attr: "spiffeEntryExpiresAt"})
  `entryExpiresAt`?: string;

  @fromAttr(#{attr: "spiffeRevisionNumber"})
  `revisionNumber`?: string;

  @fromAttr(#{attr: "spiffeOrigin"})
  `origin`?: string;

  @fromAttr(#{attr: "spiffeSvidsIssued"})
  `svidsIssued`?: string;

  @fromAttr(#{attr: "spiffeLastSvidAt"})
  `lastSvidAt`?: string;

  @fromAttr(#{attr: "spiffeCreatedAt"})
  `createdAt`?: string;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "spiffeAgentId"})
  `agentId`?: string;

  @fromAttr(#{attr: "spiffeAttestationType"})
  `attestationType`?: string;

  @fromAttr(#{attr: "spiffeAgentSelector"})
  `agentSelector`?: string[];

  @fromAttr(#{attr: "spiffeAgentBanned"})
  `agentBanned`?: string;

  @fromAttr(#{attr: "spiffeAgentCanReattest"})
  `agentCanReattest`?: string;

  @fromAttr(#{attr: "spiffeAgentSvidHash"})
  `agentSvidHash`?: string;

  @fromAttr(#{attr: "spiffeAgentExpiresAt"})
  `agentExpiresAt`?: string;

  @fromAttr(#{attr: "spiffeFirstSeen"})
  `firstSeen`?: string;

  @fromAttr(#{attr: "spiffeLastSeen"})
  `lastSeen`?: string;

  @fromAttr(#{attr: "spiffeAttestations"})
  `attestations`?: string;
}

@domain(#{
  area: "Directory",
  entry: "attributeSource",
  what: "An operator database a realm reads attributes from."
})
model AttributeSource {
  @fromAttr(#{attr: "cn"})
  `cn`?: string[];

  @fromAttr(#{attr: "stsAttributeSourceData"})
  `data`?: string;

  @fromAttr(#{attr: "stsAttributeSourced"})
  `d`?: string[];

  @fromAttr(#{attr: "stsAttributeSourceSeen"})
  `seen`?: string[];
}

@domain(#{
  area: "Federation",
  entry: "claimProvider",
  what: "An OpenID Connect claims provider."
})
model ClaimProvider {
  @fromAttr(#{attr: "stsClaimProviderData"})
  `data`?: string;

  @fromAttr(#{attr: "stsClaimProviderSecret", secret: true})
  `secret`?: string;
}

@domain(#{
  area: "Federation",
  entry: "kerberosTrust",
  what: "A Kerberos trust with another realm."
})
model KerberosTrust {
  @fromAttr(#{attr: "stsKrb5TrustData"})
  `data`?: string;

  @fromAttr(#{attr: "stsKrb5TrustKeys", secret: true})
  `keys`?: string;

  @fromAttr(#{attr: "trustPartner"})
  `trustPartner`?: string;

  @fromAttr(#{attr: "flatName"})
  `flatName`?: string;

  @fromAttr(#{attr: "securityIdentifier"})
  `securityIdentifier`?: string;

  @fromAttr(#{attr: "trustDirection"})
  `trustDirection`?: integer;

  @fromAttr(#{attr: "trustAttributes"})
  `trustAttributes`?: integer;

  @fromAttr(#{attr: "trustType"})
  `trustType`?: integer;
}

@domain(#{
  area: "Federation",
  entry: "oidfed",
  what: "An OpenID Federation entity this realm holds."
})
model OpenIdFederationEntity {
  @fromAttr(#{attr: "stsOidfedKind"})
  `kind`?: string;

  @fromAttr(#{attr: "stsOidfedEntityId"})
  `entityId`?: string;

  @fromAttr(#{attr: "stsOidfedData"})
  `data`?: string;

  @fromAttr(#{attr: "stsOidfedKeys", secret: true})
  `keys`?: string[];

  @fromAttr(#{attr: "stsOidfedEvent"})
  `event`?: string[];
}

@domain(#{
  area: "Directory",
  entry: "operational",
  what: "What the directory keeps about any entry."
})
model DirectoryEntry {
  @fromAttr(#{attr: "entryUUID"})
  entryUuid?: string;

  @fromAttr(#{attr: "createTimestamp"})
  `createTimestamp`?: string;

  @fromAttr(#{attr: "modifyTimestamp"})
  `modifyTimestamp`?: string;

  @fromAttr(#{attr: "entryDN"})
  `entryDN`?: string;

  @fromAttr(#{attr: "stsEntryUuidAlias"})
  `stsEntryUuidAlias`?: string[];

  @fromAttr(#{attr: "memberOf"})
  `memberOf`?: string[];
}

@domain(#{
  area: "Policy",
  entry: "policy.attributes",
  what: "What every person in a realm must hold."
})
model AttributePolicy {
  @fromAttr(#{attr: "stsAttributeRequired"})
  `required`?: string[];

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "stsAttributeLabel"})
  `label`?: string;

  @fromAttr(#{attr: "stsAttributeSyntax"})
  `syntax`?: string;

  @fromAttr(#{attr: "stsAttributeSingleValued"})
  `singleValued`?: boolean;

  @fromAttr(#{attr: "stsAttributePortalVisible"})
  `portalVisible`?: boolean;

  @fromAttr(#{attr: "stsAttributePortalEditable"})
  `portalEditable`?: boolean;

  @fromAttr(#{attr: "stsAttributePolicyPrecedence"})
  `policyPrecedence`?: integer;

  @fromAttr(#{attr: "stsAttributePolicy"})
  `policy`?: string;
}

@domain(#{
  area: "Policy",
  entry: "policy.authn",
  what: "Which mechanisms a sign-in may use."
})
model AuthenticationPolicy {
  @fromAttr(#{attr: "stsAuthnRequireSecondFactor"})
  `requireSecondFactor`?: string;

  @fromAttr(#{attr: "stsAuthnRequireSecondFactorForAdministrators"})
  `requireSecondFactorForAdministrators`?: string;

  @fromAttr(#{attr: "stsAuthnPasswordPrimary"})
  `passwordPrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnPasswordSecondFactor"})
  `passwordSecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnPasskeyPrimary"})
  `passkeyPrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnSecurityKeySecondFactor"})
  `securityKeySecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnTotpSecondFactor"})
  `totpSecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnRecoveryCodeSecondFactor"})
  `recoveryCodeSecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnEmailCodePrimary"})
  `emailCodePrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnEmailCodeSecondFactor"})
  `emailCodeSecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnEmailLinkPrimary"})
  `emailLinkPrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnEmailLinkSecondFactor"})
  `emailLinkSecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnCertificatePrimary"})
  `certificatePrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnKerberosPrimary"})
  `kerberosPrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnWalletPrimary"})
  `walletPrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnWalletSecondFactor"})
  `walletSecondFactor`?: boolean;

  @fromAttr(#{attr: "stsAuthnFederationPrimary"})
  `federationPrimary`?: boolean;

  @fromAttr(#{attr: "stsAuthnEmailCodeTtlS"})
  `emailCodeTtlS`?: string;

  @fromAttr(#{attr: "stsAuthnEmailCodeAttempts"})
  `emailCodeAttempts`?: string;

  @fromAttr(#{attr: "stsAuthnEmailResendS"})
  `emailResendS`?: string;

  @fromAttr(#{attr: "stsAuthnEmailFailureLimit"})
  `emailFailureLimit`?: string;

  @fromAttr(#{attr: "stsAuthnRememberedBrowserSkipsSecondFactor"})
  `rememberedBrowserSkipsSecondFactor`?: string;

  @fromAttr(#{attr: "stsAuthnRememberedBrowserDays"})
  `rememberedBrowserDays`?: string;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "stsAuthnPolicyMechanism"})
  `policyMechanism`?: string[];

  @fromAttr(#{attr: "stsAuthnPolicySecondFactor"})
  `policySecondFactor`?: string[];

  @fromAttr(#{attr: "stsAuthnPolicyPrecedence"})
  `policyPrecedence`?: integer;

  @fromAttr(#{attr: "stsMailFactor"})
  `stsMailFactor`?: string;

  @fromAttr(#{attr: "stsMailFactorFailures"})
  `stsMailFactorFailures`?: integer;
}

@domain(#{
  area: "Policy",
  entry: "policy.locale",
  what: "Which languages a realm offers."
})
model LocalePolicy {
  @fromAttr(#{attr: "stsLocaleDefault"})
  `default`?: string;

  @fromAttr(#{attr: "stsLocalePopulatePreferredLanguage"})
  `populatePreferredLanguage`?: string;

  @fromAttr(#{attr: "stsLocalePrecedence"})
  `precedence`?: integer;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "stsPreferredLanguagePopulated"})
  `stsPreferredLanguagePopulated`?: string;
}

@domain(#{
  area: "Policy",
  entry: "policy.passkey",
  what: "What a passkey must be."
})
model PasskeyPolicy {
  @fromAttr(#{attr: "stsPasskeyAllowUsernameless"})
  `allowUsernameless`?: string;

  @fromAttr(#{attr: "stsPasskeyRequireUsernameless"})
  `requireUsernameless`?: string;

  @fromAttr(#{attr: "stsPasskeySecurityKeyResidentKey"})
  `securityKeyResidentKey`?: string;

  @fromAttr(#{attr: "stsPasskeyBackupEligibility"})
  `backupEligibility`?: string;

  @fromAttr(#{attr: "stsPasskeyEnforcePinLength"})
  `enforcePinLength`?: string;

  @fromAttr(#{attr: "stsPasskeyMinPinLength"})
  `minPinLength`?: string;

  @fromAttr(#{attr: "stsPasskeyPinLengthOnlyIfSupported"})
  `pinLengthOnlyIfSupported`?: string;

  @fromAttr(#{attr: "stsPasskeyEnforceAttestationAtSignIn"})
  `enforceAttestationAtSignIn`?: string;

  @fromAttr(#{attr: "stsPasskeyPostQuantumRequired"})
  `postQuantumRequired`?: string;

  @fromAttr(#{attr: "stsPasskeyPostQuantumAllowCredentials"})
  `postQuantumAllowCredentials`?: string;

  @fromAttr(#{attr: "stsPasskeyRegistrationAlgorithms"})
  `registrationAlgorithms`?: string;

  @fromAttr(#{attr: "stsPasskeyRegistrationMode"})
  `registrationMode`?: string;

  @fromAttr(#{attr: "stsPasskeyLanes"})
  `lanes`?: string;

  @fromAttr(#{attr: "stsPasskeyClientRules"})
  `clientRules`?: string;

  @fromAttr(#{attr: "stsPasskeyHintsPasskey"})
  `hintsPasskey`?: string;

  @fromAttr(#{attr: "stsPasskeyHintsSecurityKey"})
  `hintsSecurityKey`?: string;

  @fromAttr(#{attr: "stsPasskeyHintsSignIn"})
  `hintsSignIn`?: string;

  @fromAttr(#{attr: "stsPasskeyEnterpriseSerialAttribute"})
  `enterpriseSerialAttribute`?: string;

  @fromAttr(#{attr: "stsPasskeyUserDisplayName"})
  `userDisplayName`?: string;

  @fromAttr(#{attr: "stsPasskeyRpNameExtras"})
  `rpNameExtras`?: string;

  @fromAttr(#{attr: "stsPasskeyCredentialLabel"})
  `credentialLabel`?: string;

  @fromAttr(#{attr: "stsPasskeyAggregateDevices"})
  `aggregateDevices`?: string;

  @fromAttr(#{attr: "stsPasskeyRecoveryAssurance"})
  `recoveryAssurance`?: string;

  @fromAttr(#{attr: "stsPasskeyAttestationAlgorithms"})
  `attestationAlgorithms`?: string;

  @fromAttr(#{attr: "stsPasskeyAdminEnrolment"})
  `adminEnrolment`?: string;

  @fromAttr(#{attr: "stsPasskeyDeviceBoundRequired"})
  `deviceBoundRequired`?: string;

  @fromAttr(#{attr: "stsPasskeyPrecedence"})
  `precedence`?: integer;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "stsRecoveryPending"})
  `stsRecoveryPending`?: string;

  @fromAttr(#{attr: "stsPasswordResetSource"})
  `stsPasswordResetSource`?: string;
}

@domain(#{
  area: "Policy",
  entry: "policy.password",
  what: "What a password must be."
})
model PasswordPolicy {
  @fromAttr(#{attr: "pwdAttribute"})
  `pwdAttribute`?: string[];

  @fromAttr(#{attr: "pwdMinLength"})
  `pwdMinLength`?: string;

  @fromAttr(#{attr: "pwdInHistory"})
  `pwdInHistory`?: string;

  @fromAttr(#{attr: "stsPwdMinSymbols"})
  `stsPwdMinSymbols`?: string;

  @fromAttr(#{attr: "stsPwdRequireUppercase"})
  `stsPwdRequireUppercase`?: string;

  @fromAttr(#{attr: "stsPwdRequireDigit"})
  `stsPwdRequireDigit`?: string;

  @fromAttr(#{attr: "stsPwdGeneratedLength"})
  `stsPwdGeneratedLength`?: string;

  @fromAttr(#{attr: "stsPwdHashAlgorithm"})
  `stsPwdHashAlgorithm`?: string;

  @fromAttr(#{attr: "stsPwdArgon2Memory"})
  `stsPwdArgon2Memory`?: string;

  @fromAttr(#{attr: "stsPwdArgon2Iterations"})
  `stsPwdArgon2Iterations`?: string;

  @fromAttr(#{attr: "stsPwdArgon2Parallelism"})
  `stsPwdArgon2Parallelism`?: string;

  @fromAttr(#{attr: "stsPwdScryptLogN"})
  `stsPwdScryptLogN`?: string;

  @fromAttr(#{attr: "stsPwdScryptBlockSize"})
  `stsPwdScryptBlockSize`?: string;

  @fromAttr(#{attr: "stsPwdScryptParallelism"})
  `stsPwdScryptParallelism`?: string;

  @fromAttr(#{attr: "stsPasswordPrecedence"})
  `precedence`?: integer;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "pwdHistory", secret: true})
  `pwdHistory`?: string[];

  @fromAttr(#{attr: "pwdChangedTime"})
  `pwdChangedTime`?: string;
}

@domain(#{
  area: "Policy",
  entry: "policy.postLogin",
  what: "What is asked of a person after signing in."
})
model PostLoginPolicy {
  @fromAttr(#{attr: "stsPostLoginEnabled"})
  `enabled`?: string;

  @fromAttr(#{attr: "stsPostLoginActivity"})
  `activity`?: string;

  @fromAttr(#{attr: "stsPostLoginSnoozeDays"})
  `snoozeDays`?: string;

  @fromAttr(#{attr: "stsPostLoginGraceDays"})
  `graceDays`?: string;

  @fromAttr(#{attr: "stsPostLoginNoPasskey"})
  `noPasskey`?: string;

  @fromAttr(#{attr: "stsPostLoginMethod"})
  `method`?: string;

  @fromAttr(#{attr: "stsPostLoginAttestation"})
  `attestation`?: string;

  @fromAttr(#{attr: "stsPostLoginNoPasskeyFallback"})
  `noPasskeyFallback`?: string;

  @fromAttr(#{attr: "stsPostLoginPrecedence"})
  `precedence`?: integer;

  @fromAttr(#{attr: "description"})
  `description`?: string[];

  @fromAttr(#{attr: "stsPostLoginNoPasskeyRole"})
  `noPasskeyRole`?: string;
}

@domain(#{
  area: "Policy",
  entry: "policy.serviceAccount",
  what: "What a service account may do."
})
model ServiceAccountPolicy {
  @fromAttr(#{attr: "stsSvcAcctExemptFromSecondFactor"})
  `exemptFromSecondFactor`?: string;

  @fromAttr(#{attr: "stsSvcAcctAllowBrowserSignIn"})
  `allowBrowserSignIn`?: string;

  @fromAttr(#{attr: "stsSvcAcctAllowLdapBind"})
  `allowLdapBind`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctAllowWsTrust"})
  `allowWsTrust`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctAllowScim"})
  `allowScim`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctAllowSsf"})
  `allowSsf`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctAllowEst"})
  `allowEst`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctAllowKerberos"})
  `allowKerberos`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctAllowPasswordGrant"})
  `allowPasswordGrant`?: boolean;

  @fromAttr(#{attr: "stsSvcAcctRotationEnabled"})
  `rotationEnabled`?: string;

  @fromAttr(#{attr: "stsSvcAcctRotationIntervalDays"})
  `rotationIntervalDays`?: string;

  @fromAttr(#{attr: "stsSvcAcctRotationOverlapMinutes"})
  `rotationOverlapMinutes`?: string;

  @fromAttr(#{attr: "stsSvcAcctGeneratedLength"})
  `generatedLength`?: string;

  @fromAttr(#{attr: "stsSvcAcctRequireOwner"})
  `requireOwner`?: string;

  @fromAttr(#{attr: "stsSvcAcctRotationAlarmFailures"})
  `rotationAlarmFailures`?: string;

  @fromAttr(#{attr: "stsServiceAccountPrecedence"})
  `stsServiceAccountPrecedence`?: integer;

  @fromAttr(#{attr: "description"})
  `description`?: string[];
}
