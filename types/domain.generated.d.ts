// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/domain/ (#1390). Do not edit: change the model and
// run tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails
// when this differs.

declare namespace IyaDomain {
  /**
   * Something this service issues to or accepts from, in any protocol.
   */
  interface Application {
    identifier: string;
    displayName?: string;
    description?: string;
    homePage?: string;
    allowedProtocols?: string[];
    registered?: boolean;
    firstSeen?: string;
    lastSeen?: string;
    realm?: string;
    oauth?: OAuthClient;
    saml?: SamlServiceProvider;
    wsFederation?: WsFederationRelyingParty;
    cn?: string;
    launchProtocol?: string;
    corsOrigin?: string[];
    kind?: string[];
    protocol?: string[];
    authorizationServer?: string[];
    authentications?: string;
    sessions?: string;
    users?: string;
    lastSession?: string;
    lastUser?: string;
    registeredBy?: string;
    federationRegistration?: string;
    federationExpiresAt?: string;
    federationTrustAnchor?: string;
    redirectUriObserved?: string[];
    returnAddressObserved?: string[];
    owner?: string[];
    stsOwnerProtected?: string;
    authzenAttribute?: string[];
    authzenApplication?: string[];
    authzenCallbackUri?: string[];
    softwareStatementIssuer?: string;
    softwareStatementTrusted?: string;
    softwareStatementPublisher?: string;
    requiredRole?: string[];
    allowedToDelegateTo?: string[];
    allowedToActOnBehalfOf?: string[];
    delegationSubjectGroup?: string[];
    delegationSemantics?: string[];
    defaultDelegationSemantics?: string;
    notDelegated?: string;
    mayAct?: string;
    groupsClaim?: string;
    groupsClaimName?: string;
    groupsClaimValue?: string;
    groupsClaimFromMemberOf?: string;
    enrolledCertificate?: string[];
    enrolledPrivateKey?: string[];
    acmeEabKey?: string[];
    scepChallenge?: string[];
    certificateHostName?: string[];
    registrationJson?: string;
    registrationAccessToken?: string;
    federationPartnerId?: string[];
    ldapBindDn?: string[];
    enrollMaxCertificates?: string;
    spiffeWorkloadId?: string[];
    federationRelationship?: string[];
    federationAutoRedirect?: string;
    authnPolicy?: string;
    passkeyPolicy?: string;
    localePolicy?: string;
    passwordPolicy?: string;
    postLoginPolicy?: string;
    fgaPolicy?: string;
    fgaEnforced?: string;
    umaOwnsResources?: string;
    verifiableCredentialPartner?: VerifiableCredentialPartner;
    wsTrustRelyingParty?: WsTrustRelyingParty;
    kerberosService?: KerberosService;
    gnapClient?: GnapClient;
    scimProvisioningTarget?: ScimProvisioningTarget;
    certificateEnrollment?: CertificateEnrollment;
    secretDestination?: SecretDestination;
    sharedSignalsReceiver?: SharedSignalsReceiver;
  }

  /**
   * What every person in a realm must hold.
   */
  interface AttributePolicy {
    required?: string[];
    description?: string[];
    label?: string;
    syntax?: string;
    singleValued?: boolean;
    portalVisible?: boolean;
    portalEditable?: boolean;
    policyPrecedence?: number;
    policy?: string;
  }

  /**
   * An operator database a realm reads attributes from.
   */
  interface AttributeSource {
    cn?: string[];
    data?: string;
    d?: string[];
    seen?: string[];
  }

  /**
   * One thing that happened, as the realm's audit log records it.
   */
  interface AuditEvent {
    sequence: number;
    at: number;
    category: string;
    action: string;
    outcome: string;
    errorCode?: string;
    actor?: string;
    target?: string;
    summary: string;
  }

  /**
   * One act of proving who somebody is, recorded on the session it happened in.
   */
  interface AuthenticationEvent {
    at: number;
    methods?: string[];
    assuranceLevel?: string;
    protocol: string;
    authenticated: boolean;
    authorityKind?: string;
  }

  /**
   * Which mechanisms a sign-in may use.
   */
  interface AuthenticationPolicy {
    requireSecondFactor?: string;
    requireSecondFactorForAdministrators?: string;
    passwordPrimary?: boolean;
    passwordSecondFactor?: boolean;
    passkeyPrimary?: boolean;
    securityKeySecondFactor?: boolean;
    totpSecondFactor?: boolean;
    recoveryCodeSecondFactor?: boolean;
    emailCodePrimary?: boolean;
    emailCodeSecondFactor?: boolean;
    emailLinkPrimary?: boolean;
    emailLinkSecondFactor?: boolean;
    certificatePrimary?: boolean;
    kerberosPrimary?: boolean;
    walletPrimary?: boolean;
    walletSecondFactor?: boolean;
    federationPrimary?: boolean;
    emailCodeTtlS?: string;
    emailCodeAttempts?: string;
    emailResendS?: string;
    emailFailureLimit?: string;
    rememberedBrowserSkipsSecondFactor?: string;
    rememberedBrowserDays?: string;
    description?: string[];
    policyMechanism?: string[];
    policySecondFactor?: string[];
    policyPrecedence?: number;
    stsMailFactor?: string;
    stsMailFactorFailures?: number;
  }

  /**
   * Certificate enrollment by EST, ACME or SCEP.
   */
  interface CertificateEnrollment {
    allowedProfiles?: string[];
    defaultProfile?: string;
    certificateLifetimeDays?: string;
    allowedProfiles2?: string[];
    defaultProfile2?: string;
    certificateLifetimeDays2?: string;
    allowedProfiles3?: string[];
    defaultProfile3?: string;
    certificateLifetimeDays3?: string;
    basicAuthentication?: string;
    certificateAuthentication?: string;
    serverKeyGeneration?: string;
  }

  /**
   * An OpenID Connect claims provider.
   */
  interface ClaimProvider {
    data?: string;
    secret?: string;
  }

  /**
   * Everything a person proves themselves with: the concept a User deliberately
   * is not.
   */
  interface Credential {
    passwordHash?: string;
    authenticatorApp?: string;
    passkeys?: string[];
    recoveryCodes?: string;
    appPasswords?: string;
    passwordChanged?: string;
    passwordMustChange?: boolean;
    lockedSince?: string;
    userCertificate?: string[];
    krb5KeyInfo?: string;
    hobaPublicKey?: string[];
    activationExpires?: string;
    passwordResetExpires?: string;
    pwdHistory?: string[];
    activationToken?: string;
    profilePhoto?: string;
    passwordResetToken?: string;
    krb5Keys?: string;
    selfIssuedSubject?: string[];
    publishedDid?: string[];
    cibaUserCode?: string;
    androidAttestedCredential?: string[];
    webauthnUserHandle?: string;
    webauthnPqcUserHandle?: string;
    mailVerifyToken?: string;
    mailVerifyExpires?: string;
    mailVerifyAddress?: string;
    pseudonym?: string[];
    pseudonymVerifyToken?: string;
    pseudonymVerifyExpires?: string;
    pseudonymVerifyAddress?: string;
    assertionIssuer?: string[];
    assertionKeyPair?: string[];
    assertionPrivateKey?: string[];
    samlAssertionIssuer?: string[];
    samlAssertionKeyPair?: string[];
    samlAssertionPrivateKey?: string[];
    enrolledCertificate?: string[];
    enrolledPrivateKey?: string[];
    acmeEabKey?: string[];
    scepChallenge?: string[];
    certificateHostName?: string[];
    idaVerification?: string;
    claimSourceTokens?: string;
  }

  /**
   * A device registered in a realm, and what is known about its state.
   */
  interface Device {
    identifier: string;
    owner?: string;
    ownerKind?: string;
    description?: string;
    applications?: string[];
    compliance?: string;
    status?: string;
    riskLevel?: string;
    platform?: string;
    lastUsed?: string;
    realm?: string;
    key?: string[];
    keyThumbprint?: string[];
    credentialId?: string[];
    androidKey?: string[];
    attestation?: string;
    complianceChange?: string;
    statusChange?: string;
    riskChange?: string;
    browser?: string;
    model?: string;
    os?: string;
    enrolment?: string;
    secretHash?: string;
    session?: string;
  }

  /**
   * What the directory keeps about any entry.
   */
  interface DirectoryEntry {
    createTimestamp?: string;
    modifyTimestamp?: string;
    entryDN?: string;
    stsEntryUuidAlias?: string[];
    memberOf?: string[];
  }

  /**
   * An agreement with one partner, in either direction and one protocol.
   */
  interface FederationRelationship {
    identifier: string;
    name?: string;
    role?: string;
    protocol?: string;
    provider?: string;
    peer?: string;
    localEntityId?: string;
    enabled?: boolean;
    clientId?: string;
    clientSecret?: string;
    authorizationUrl?: string;
    tokenUrl?: string;
    jwksUri?: string;
    realm?: string;
    cn?: string;
    description?: string[];
    userinfoUrl?: string;
    emailsUrl?: string;
    jwks?: string;
    trustAnchor?: string;
    signingCertificate?: string;
    responseMode?: string;
    allowedTenants?: string[];
    teamId?: string;
    keyId?: string;
    clientSigningKey?: string;
    authorizeParams?: string[];
    tokenAuth?: string;
    scope?: string;
    responseType?: string;
    idTokenSignedResponseAlg?: string;
    userinfoSignedResponseAlg?: string;
    refreshTokens?: string;
    refreshEverySeconds?: string;
    register?: string;
    registeredIssuer?: string;
    requestObject?: string;
    requestObjectSigningAlg?: string;
    webFinger?: string;
    discovery?: string;
    initiateLogin?: string;
    binding?: string;
    signRequest?: string;
    usernameSource?: string;
    subjectClaim?: string;
    attributeMap?: string[];
    autocreateUsers?: string;
    updateUserAttributes?: string;
    provisionGroups?: string;
    provisionCap?: string;
    provisionIdleMinutes?: string;
    subjectPolicy?: string;
    subjectGroup?: string[];
    subjectDomain?: string[];
    homeRealmDomain?: string[];
    subjectPattern?: string;
    mayAssertAdministrators?: string;
    signalEmailMatch?: string;
    signalsEnabled?: string;
    signalsIssuer?: string;
    signalsDelivery?: string;
    signalsEvents?: string[];
    signalsTokenUrl?: string;
    signalsClientId?: string;
    signalsClientSecret?: string;
    signalsScope?: string;
    signalsBearer?: string;
    sloUrl?: string;
    sloBinding?: string;
    endSessionUrl?: string;
    acceptSignout?: string;
    requireSignedLogout?: string;
    encryptionKeyType?: string;
    keyManagementAlgorithm?: string;
    contentEncryptionAlgorithm?: string;
    allowUnencrypted?: string;
    encryptionKey?: string[];
    allowUnsolicited?: string;
    application?: string;
    authnMechanism?: string;
    authnRelationship?: string;
    release?: string[];
    firstSeen?: string;
    lastSeen?: string;
    authentications?: string;
    users?: string;
    lastUser?: string;
    applicationUse?: string[];
    lastError?: string;
    lastErrorAt?: string;
  }

  /**
   * A GNAP client.
   */
  interface GnapClient {
    claimsAccessToken?: string;
    instanceId?: string;
    key?: string;
    keyIdentity?: string;
    keyReference?: string;
    keyProof?: string;
    mtlsTrust?: string;
    symmetricKey?: string;
    symmetricAlg?: string;
    classId?: string;
    displayUri?: string;
    logoUri?: string;
    finishUri?: string[];
    interactionStartModes?: string[];
    allowedAccess?: string[];
    bearerTokens?: string;
    skipInteraction?: string;
    accessTokenFormat?: string;
    accessTokenLifetimeS?: string;
    resourceServerUri?: string[];
    ownerLookupUri?: string;
    jweKey?: string;
    macaroonKey?: string;
    scopedSignals?: string;
  }

  /**
   * A set of people, and the policies that apply to its members. A group grants
   * nothing by being a group.
   */
  interface Group {
    name: string;
    description?: string;
    members?: string[];
    realm?: string;
    uniqueMember?: string[];
    memberUid?: string[];
    stsPasskeyPolicy?: string;
    stsLocalePolicy?: string;
    stsPasswordPolicy?: string;
    stsAuthnPolicy?: string;
    stsPostLoginPolicy?: string;
    stsAttributePolicy?: string;
    federationRelationship?: string[];
  }

  /**
   * A token this service issued, as its register remembers it. The signed value
   * is not kept.
   */
  interface IssuedToken {
    id: string;
    kind: string;
    subject: string;
    issuer: string;
    clientId?: string;
    audience?: string;
    scope?: string;
    expires: number;
    sessionId?: string;
    grantId?: string;
    revoked: boolean;
  }

  /**
   * A Kerberos service principal.
   */
  interface KerberosService {
    servicePrincipalName?: string[];
    claimsPac?: string;
    trustedForDelegation?: string;
    s4uSelfRealm?: string[];
    foreignTgtDelegation?: string;
    serviceKeys?: string;
    serviceKeyInfo?: string;
  }

  /**
   * A Kerberos trust with another realm.
   */
  interface KerberosTrust {
    data?: string;
    keys?: string;
    trustPartner?: string;
    flatName?: string;
    securityIdentifier?: string;
    trustDirection?: number;
    trustAttributes?: number;
    trustType?: number;
  }

  /**
   * Which languages a realm offers.
   */
  interface LocalePolicy {
    default?: string;
    populatePreferredLanguage?: string;
    precedence?: number;
    description?: string[];
    stsPreferredLanguagePopulated?: string;
  }

  /**
   * What an OAuth 2.0 client or OpenID Connect relying party is registered
   * with.
   */
  interface OAuthClient {
    clientIds?: string[];
    clientSecrets?: string[];
    redirectUris?: string[];
    postLogoutRedirectUris?: string[];
    grantTypes?: string[];
    responseTypes?: string[];
    tokenEndpointAuthMethods?: string[];
    idTokenSigningAlgorithm?: string;
    audience?: string[];
    claimsRedirectUri?: string[];
    frontchannelLogoutUri?: string;
    frontchannelLogoutSessionRequired?: string;
    backchannelLogoutUri?: string;
    backchannelLogoutSessionRequired?: string;
    allowedTokenResponseTypes?: string[];
    grantTypeObserved?: string[];
    responseTypeObserved?: string[];
    scope?: string[];
    allowedScope?: string[];
    permissionBaseUri?: string;
    permission?: string[];
    roleGatedPermission?: string[];
    resourceMetadata?: string;
    resourceMetadataUrl?: string;
    delegatedPermission?: string[];
    globalConsent?: string[];
    globalConsentWithdrawn?: string[];
    nativeSso?: string;
    nativeSsoGroup?: string;
    backchannelTokenDeliveryMode?: string;
    backchannelClientNotificationEndpoint?: string;
    commandEndpoint?: string;
    backchannelAuthenticationRequestSigningAlg?: string;
    backchannelUserCodeParameter?: string;
    subjectType?: string;
    sectorIdentifierUri?: string;
    didClaimWithPairwise?: string;
    tokenEndpointAuthSigningAlg?: string;
    jwks?: string;
    jwksUri?: string;
    introspectionSignedResponseAlg?: string;
    introspectionEncryptedResponseAlg?: string;
    introspectionEncryptedResponseEnc?: string;
    requestUri?: string[];
    requestObjectSigningAlg?: string;
    requestObjectEncryptionAlg?: string;
    requestObjectEncryptionEnc?: string;
    requireSignedRequestObject?: string;
    requirePushedAuthorizationRequests?: string;
    httpSignedRequests?: string;
    authorizationDetailsType?: string[];
    authorizationDetailsTypes?: string[];
    stepUpAcrValues?: string;
    stepUpMaxAge?: string;
    idTokenEncryptedResponseAlg?: string;
    idTokenEncryptedResponseEnc?: string;
    userinfoSignedResponseAlg?: string;
    userinfoEncryptedResponseAlg?: string;
    userinfoEncryptedResponseEnc?: string;
    authorizationSignedResponseAlg?: string;
    authorizationEncryptedResponseAlg?: string;
    authorizationEncryptedResponseEnc?: string;
    defaultAcrValues?: string;
    defaultMaxAge?: string;
    assertionIssuer?: string[];
    assertionJwks?: string;
    assertionCertificate?: string;
    assertionCertificateChain?: string;
    assertionPrivateKey?: string;
    assertionKid?: string;
    assertionExpiresAt?: string;
    assertionKeySource?: string;
    samlAssertionIssuer?: string[];
    samlAssertionSigningCertificate?: string;
    samlAssertionCertificate?: string;
    samlAssertionCertificateChain?: string;
    samlAssertionPrivateKey?: string;
    samlAssertionThumbprint?: string;
    samlAssertionExpiresAt?: string;
    samlAssertionKeySource?: string;
    softwareStatementIssuer?: string[];
    issuedSoftwareStatement?: string;
    tlsClientAuthSubjectDn?: string;
    tlsClientAuthSanDns?: string;
    tlsClientAuthSanUri?: string;
    tlsClientAuthSanIp?: string;
    tlsClientAuthSanEmail?: string;
    tlsClientCertificateBoundAccessTokens?: string;
    tlsClientCertificateThumbprint?: string;
    confidential?: string;
    accessTokenTtlS?: string;
    idTokenTtlS?: string;
    refreshTokenTtlS?: string;
    refreshIdleSeconds?: string;
    claimsAccessToken?: string;
    claimsIdToken?: string;
    claimsUserinfo?: string;
    claimAttributesAccessToken?: string;
    claimAttributesIdToken?: string;
    claimAttributesUserinfo?: string;
    claimsCombineAccessToken?: string;
    claimsCombineIdToken?: string;
    claimsCombineUserinfo?: string;
    accessTokenClaim?: string[];
    permissionClaims?: string;
    accessTokenClaimsCombine?: string;
    revokeRefreshOnLogout?: string;
    thirdPartyInitiatedLogin?: string;
    spInitiatedSso?: string;
    initiateLoginUri?: string;
    logoUri?: string;
    policyUri?: string;
    tosUri?: string;
    tokenExchangeRefreshToken?: string;
  }

  /**
   * An OpenID Federation entity this realm holds.
   */
  interface OpenIdFederationEntity {
    kind?: string;
    entityId?: string;
    data?: string;
    keys?: string[];
    event?: string[];
  }

  /**
   * What a passkey must be.
   */
  interface PasskeyPolicy {
    allowUsernameless?: string;
    requireUsernameless?: string;
    securityKeyResidentKey?: string;
    backupEligibility?: string;
    enforcePinLength?: string;
    minPinLength?: string;
    pinLengthOnlyIfSupported?: string;
    enforceAttestationAtSignIn?: string;
    postQuantumRequired?: string;
    postQuantumAllowCredentials?: string;
    registrationAlgorithms?: string;
    registrationMode?: string;
    lanes?: string;
    clientRules?: string;
    hintsPasskey?: string;
    hintsSecurityKey?: string;
    hintsSignIn?: string;
    enterpriseSerialAttribute?: string;
    userDisplayName?: string;
    rpNameExtras?: string;
    credentialLabel?: string;
    aggregateDevices?: string;
    recoveryAssurance?: string;
    attestationAlgorithms?: string;
    adminEnrolment?: string;
    deviceBoundRequired?: string;
    precedence?: number;
    description?: string[];
    stsRecoveryPending?: string;
    stsPasswordResetSource?: string;
  }

  /**
   * What a password must be.
   */
  interface PasswordPolicy {
    pwdAttribute?: string[];
    pwdMinLength?: string;
    pwdInHistory?: string;
    stsPwdMinSymbols?: string;
    stsPwdRequireUppercase?: string;
    stsPwdRequireDigit?: string;
    stsPwdGeneratedLength?: string;
    stsPwdHashAlgorithm?: string;
    stsPwdArgon2Memory?: string;
    stsPwdArgon2Iterations?: string;
    stsPwdArgon2Parallelism?: string;
    stsPwdScryptLogN?: string;
    stsPwdScryptBlockSize?: string;
    stsPwdScryptParallelism?: string;
    precedence?: number;
    description?: string[];
    pwdHistory?: string[];
    pwdChangedTime?: string;
  }

  /**
   * What this service keeps about a person beyond their profile and
   * credentials: federation links, delegation, consent and SPIFFE subjects.
   */
  interface PersonRecord {
    x509subject?: string[];
    x509issuer?: string[];
    x509serialNumber?: string[];
    x509notBefore?: string[];
    x509notAfter?: string[];
    x509fingerprint256?: string[];
    x509svidsIssued?: number;
    x509firstIssued?: string;
    x509lastIssued?: string;
    didSubject?: string[];
    didMethod?: string[];
    spiffeSubject?: string[];
    spiffePath?: string;
    spiffeTrustDomain?: string;
    spiffeCredentialStatus?: string;
    spiffeCredentialStatusReason?: string;
    spiffeRevokedAt?: string;
    authnMethod?: string[];
    mfaAuthenticated?: boolean;
    mfaLastAuthTime?: string;
    federationIssuer?: string[];
    federationLink?: string[];
    federationLastSeen?: string;
    federationAttribute?: string[];
    provisionedBy?: string;
    oauthConsent?: string[];
    oauthConsentWithdrawn?: string[];
    oauthConsentApplied?: string[];
    bootstrapAdministrator?: boolean;
    consoleClaimedAt?: string;
    mfaRequired?: boolean;
    notDelegated?: boolean;
    mayAct?: string;
    delegationSemantics?: string[];
    defaultDelegationSemantics?: string;
    mailVerified?: string;
    audSub?: string[];
  }

  /**
   * What is asked of a person after signing in.
   */
  interface PostLoginPolicy {
    enabled?: string;
    activity?: string;
    snoozeDays?: string;
    graceDays?: string;
    noPasskey?: string;
    method?: string;
    attestation?: string;
    noPasskeyFallback?: string;
    precedence?: number;
    description?: string[];
    noPasskeyRole?: string;
  }

  /**
   * A set of permissions and who holds it.
   */
  interface Role {
    name: string;
    displayName?: string;
    description?: string;
    memberUsers?: string[];
    memberGroups?: string[];
    memberApplications?: string[];
    permissions?: string[];
    realm?: string;
    roleConferredBy?: string[];
    roleApplication?: string;
    roleAllowedMemberType?: string[];
    owner?: string[];
    stsOwnerProtected?: boolean;
  }

  /**
   * What a SAML service provider is registered with.
   */
  interface SamlServiceProvider {
    entityIds?: string[];
    assertionConsumerServices?: string[];
    assertionConsumerService?: string[];
    singleLogoutService?: string[];
    nameIdFormat?: string[];
    responseBinding?: string[];
    signingCertificate?: string[];
    observedSigningCertificate?: string;
    authnRequestVerification?: string;
    spMetadataUrl?: string;
    spMetadata?: string;
    encryptionCertificate?: string;
    sloEndpoint?: string[];
    spNameIdFormat?: string[];
    spAuthnRequestsSigned?: string;
    spWantAssertionsSigned?: string;
    spWantAssertionsEncrypted?: string;
    spMetadataValidUntil?: string;
    spMetadataCacheDuration?: string;
    spMetadataConsumedAt?: string;
    spMetadataSignature?: string;
    spMetadataSigningCertificate?: string;
    f2EncryptAssertion?: string;
    f2EncryptionAlgorithm?: string;
    f2KeyTransportAlgorithm?: string;
    f2EncryptLogoutNameId?: string;
    f2CustomAttributes?: string;
    f11CustomAttributes?: string;
    f2ClaimAttributes?: string;
    f11ClaimAttributes?: string;
    f2ClaimsCombine?: string;
    f11ClaimsCombine?: string;
    f2AssertionLifetimeMin?: string;
    f2SignAssertion?: string;
    f2SignResponse?: string;
    f2NameIdFormat?: string;
    f2ArtifactTtlS?: string;
    f11AssertionLifetimeMin?: string;
    f11SignAssertion?: string;
    f11SignResponse?: string;
    f11NameIdFormat?: string;
    f11ArtifactTtlS?: string;
    f2IdpInitiatedSso?: string;
    f2SpInitiatedSso?: string;
    f11IdpInitiatedSso?: string;
    f11SpInitiatedSso?: string;
    authnRequestSigned?: string;
  }

  /**
   * Where people are provisioned by SCIM.
   */
  interface ScimProvisioningTarget {
    clientId?: string[];
    clientBaseUrl?: string;
    clientEnabled?: string;
    clientAuthMethod?: string;
    clientUsername?: string;
    clientPassword?: string;
    clientTokenEndpoint?: string;
    clientOAuthClientId?: string;
    clientOAuthClientSecret?: string;
    clientOAuthClientAuth?: string;
    clientOAuthScope?: string;
    clientOAuthResource?: string;
    clientTlsSource?: string;
    clientTlsCertificate?: string;
    clientTlsPrivateKey?: string;
    clientCaCertificates?: string;
    clientScopeMode?: string;
    clientScopeGroups?: string[];
    clientScopeFilter?: string;
    clientGroupMode?: string;
    clientGroups?: string[];
    clientDeprovision?: string;
    clientReconcileMinutes?: string;
    clientJurisdiction?: string;
    clientCells?: string[];
    clientMaxRequestsPerSecond?: string;
  }

  /**
   * Where a rotated password is pushed.
   */
  interface SecretDestination {
    destProvider?: string;
    destPayload?: string;
    destRegion?: string;
    destProject?: string;
    destEndpoint?: string;
    destMount?: string;
    destField?: string;
    destDirectory?: string;
    destCaCertificates?: string;
    destCredential?: string;
  }

  /**
   * An account a program uses, rotated by this service and owned by a person.
   */
  interface ServiceAccount {
    owners?: string[];
    secretDestination?: string;
    secretName?: string;
    rotationFailures?: number;
    realm?: string;
    serviceAccount?: boolean;
    passwordRotatedAt?: string;
    previousPassword?: string;
    previousPasswordExpires?: string;
    rotationLastError?: string;
    rotationLastAttempt?: string;
    ownerProtected?: boolean;
    serviceAccountPolicy?: string;
  }

  /**
   * What a service account may do.
   */
  interface ServiceAccountPolicy {
    exemptFromSecondFactor?: string;
    allowBrowserSignIn?: string;
    allowLdapBind?: boolean;
    allowWsTrust?: boolean;
    allowScim?: boolean;
    allowSsf?: boolean;
    allowEst?: boolean;
    allowKerberos?: boolean;
    allowPasswordGrant?: boolean;
    rotationEnabled?: string;
    rotationIntervalDays?: string;
    rotationOverlapMinutes?: string;
    generatedLength?: string;
    requireOwner?: string;
    rotationAlarmFailures?: string;
    stsServiceAccountPrecedence?: number;
    description?: string[];
  }

  /**
   * An authenticated identity: the internal record every issued artifact is a
   * projection of.
   */
  interface Session {
    id: string;
    username: string;
    subjectId: string;
    authenticated: boolean;
    authTime: number;
    methods?: string[];
    assuranceLevel?: string;
    startedThrough: string;
    startedAt: number;
    expires: number;
    lastSeenAt: number;
    events: AuthenticationEvent[];
  }

  /**
   * A Shared Signals receiver or transmitter partner.
   */
  interface SharedSignalsReceiver {
    receiverId?: string[];
    deliveryEndpoint?: string[];
    allowedEvents?: string[];
    caepIncludeReasons?: string;
    caepReasonLanguage?: string;
    caepOmitEventTimestamp?: string;
    riscIncludeReasons?: string;
    riscReasonLanguage?: string;
    riscOmitEventTimestamp?: string;
    signingAlgorithm?: string;
    minVerificationInterval?: string;
    inactivityTimeoutS?: string;
    inactivityAction?: string;
    verificationEveryS?: string;
    streamStatusOnCreate?: string;
    maxStreams?: string;
    maxSubjectsPerStream?: string;
    maxQueuedEvents?: string;
    pollMaxEvents?: string;
    deadLetterMaxPerStream?: string;
    pushTimeoutMs?: string;
    pushRetries?: string;
    pushRetryDelayMs?: string;
  }

  /**
   * A certificate authority a realm trusts to sign what it is sent.
   */
  interface SignerTrustAnchor {
    certificate: string;
    fingerprint?: string;
    addedBy?: string;
    kind?: string;
    purpose?: string;
    realm?: string;
  }

  /**
   * A SPIFFE registration entry.
   */
  interface SpiffeRegistration {
    entryId?: string;
    cn?: string;
    id?: string;
    parentId?: string;
    selector?: string[];
    x509SvidTtl?: string;
    jwtSvidTtl?: string;
    dnsName?: string[];
    federatesWith?: string[];
    hint?: string;
    admin?: string;
    downstream?: string;
    storeSvid?: string;
    entryExpiresAt?: string;
    revisionNumber?: string;
    origin?: string;
    svidsIssued?: string;
    lastSvidAt?: string;
    createdAt?: string;
    description?: string[];
    agentId?: string;
    attestationType?: string;
    agentSelector?: string[];
    agentBanned?: string;
    agentCanReattest?: string;
    agentSvidHash?: string;
    agentExpiresAt?: string;
    firstSeen?: string;
    lastSeen?: string;
    attestations?: string;
  }

  /**
   * A certificate authority a realm trusts for client certificates.
   */
  interface TrustAnchor {
    certificate: string;
    fingerprint?: string;
    addedBy?: string;
    realm?: string;
  }

  /**
   * A person this service authenticates, as every protocol projects them.
   */
  interface User {
    entryUuid: string;
    username: string;
    displayName?: string;
    givenName?: string;
    familyName?: string;
    email?: string;
    preferredLanguage?: string;
    realm?: string;
    cn?: string[];
    title?: string[];
    employeeType?: string[];
    telephoneNumber?: string[];
    mobile?: string[];
    street?: string[];
    l?: string[];
    st?: string[];
    postalCode?: string[];
    c?: string;
    postalAddress?: string[];
    o?: string[];
    ou?: string[];
    departmentNumber?: string[];
    employeeNumber?: string;
    labeledURI?: string[];
    manager?: string[];
    schacDateOfBirth?: string;
    schacCountryOfCitizenship?: string[];
    schacPersonalTitle?: string[];
    salutation?: string[];
    birthFamilyName?: string[];
    birthGivenName?: string[];
    birthMiddleName?: string[];
    alsoKnownAs?: string[];
    placeOfBirthCountry?: string;
    placeOfBirthRegion?: string;
    placeOfBirthLocality?: string;
    schacGender?: string;
    middleName?: string;
    timeZone?: string;
    pictureUrl?: string;
    profileUrl?: string;
    scimExternalId?: string;
    userPrincipalName?: string;
  }

  /**
   * Decentralized identifiers and verifiable credentials.
   */
  interface VerifiableCredentialPartner {
    credentialClaimAttributes?: string;
    clientId?: string[];
    publicKeyJwk?: string[];
    privateKeys?: string;
    service?: string[];
    alsoKnownAs?: string[];
  }

  /**
   * What a WS-Federation relying party is registered with.
   */
  interface WsFederationRelyingParty {
    realms?: string[];
    replyUrls?: string[];
    assertionLifetimeMin?: string;
    idpInitiatedSso?: string;
    spInitiatedSso?: string;
    signOutUri?: string[];
  }

  /**
   * A WS-Trust relying party.
   */
  interface WsTrustRelyingParty {
    appliesTo?: string[];
    jwtScope?: string[];
  }

  /**
   * A remote policy enforcement point.
   */
  interface XacmlPep {
    identity?: string;
    certificateSubject?: string;
    thumbprint?: string;
    authenticated?: boolean;
    notifyUrl?: string;
    bias?: string;
    resource?: string;
    enabled?: boolean;
    registeredAt?: string;
    lastSeen?: string;
    syncToken?: string;
    policyCount?: number;
    decisions?: number;
    allowed?: number;
    refused?: number;
    undischargeable?: number;
    version?: string;
    lastNotify?: string;
    description?: string[];
  }

  /**
   * An XACML 3.0 policy or policy set this realm evaluates.
   */
  interface XacmlPolicy {
    identifier: string;
    document?: string;
    version?: string;
    kind?: string;
    combiningAlgorithm?: string;
    enabled?: boolean;
    isRoot?: boolean;
    realm?: string;
    description?: string[];
    application?: string;
    orphanedAt?: string;
  }

  interface Concepts {
    Application: Application;
    AttributePolicy: AttributePolicy;
    AttributeSource: AttributeSource;
    AuditEvent: AuditEvent;
    AuthenticationEvent: AuthenticationEvent;
    AuthenticationPolicy: AuthenticationPolicy;
    CertificateEnrollment: CertificateEnrollment;
    ClaimProvider: ClaimProvider;
    Credential: Credential;
    Device: Device;
    DirectoryEntry: DirectoryEntry;
    FederationRelationship: FederationRelationship;
    GnapClient: GnapClient;
    Group: Group;
    IssuedToken: IssuedToken;
    KerberosService: KerberosService;
    KerberosTrust: KerberosTrust;
    LocalePolicy: LocalePolicy;
    OAuthClient: OAuthClient;
    OpenIdFederationEntity: OpenIdFederationEntity;
    PasskeyPolicy: PasskeyPolicy;
    PasswordPolicy: PasswordPolicy;
    PersonRecord: PersonRecord;
    PostLoginPolicy: PostLoginPolicy;
    Role: Role;
    SamlServiceProvider: SamlServiceProvider;
    ScimProvisioningTarget: ScimProvisioningTarget;
    SecretDestination: SecretDestination;
    ServiceAccount: ServiceAccount;
    ServiceAccountPolicy: ServiceAccountPolicy;
    Session: Session;
    SharedSignalsReceiver: SharedSignalsReceiver;
    SignerTrustAnchor: SignerTrustAnchor;
    SpiffeRegistration: SpiffeRegistration;
    TrustAnchor: TrustAnchor;
    User: User;
    VerifiableCredentialPartner: VerifiableCredentialPartner;
    WsFederationRelyingParty: WsFederationRelyingParty;
    WsTrustRelyingParty: WsTrustRelyingParty;
    XacmlPep: XacmlPep;
    XacmlPolicy: XacmlPolicy;
  }
}
