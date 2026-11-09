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
  }

  /**
   * What a SAML service provider is registered with.
   */
  interface SamlServiceProvider {
    entityIds?: string[];
    assertionConsumerServices?: string[];
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
  }

  /**
   * What a WS-Federation relying party is registered with.
   */
  interface WsFederationRelyingParty {
    realms?: string[];
    replyUrls?: string[];
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
  }

  interface Concepts {
    Application: Application;
    AuditEvent: AuditEvent;
    AuthenticationEvent: AuthenticationEvent;
    Credential: Credential;
    Device: Device;
    FederationRelationship: FederationRelationship;
    Group: Group;
    IssuedToken: IssuedToken;
    OAuthClient: OAuthClient;
    Role: Role;
    SamlServiceProvider: SamlServiceProvider;
    ServiceAccount: ServiceAccount;
    Session: Session;
    SignerTrustAnchor: SignerTrustAnchor;
    TrustAnchor: TrustAnchor;
    User: User;
    WsFederationRelyingParty: WsFederationRelyingParty;
    XacmlPolicy: XacmlPolicy;
  }
}
