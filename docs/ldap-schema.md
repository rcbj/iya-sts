---
title: LDAP schema
---

# LDAP schema

The embedded directory **enforces no schema**: no object class is required,
no attribute syntax is checked, and no `must`/`may` is consulted. [LDAP](ldap.md)
explains why and lists the five structural rules it enforces anyway. This
service still writes a large and consistent set of object classes and
attributes, and this page is the map of them: what each container holds, the
classes its entries carry, and every attribute this service reads or writes.

Two things to know first:

* **Names starting `sts`, `oauth`, `saml`, `fed`, `spiffe`, `xacml`, `gnap`,
  `app`, `x509`, `krb5` and similar are this service's own.** None is
  registered and none has an OID. They exist because the standards they serve
  (OAuth, WebAuthn, SPIFFE, DID Core and so on) came after the LDAP schema
  documents. Standard names (RFC 4519, RFC 2798 inetOrgPerson,
  draft-behera password policy, RFC 4530) are used wherever one fits.
* **Attribute names are case-insensitive.** The directory keeps a table of
  canonical spellings (`STANDARD_NAMES` and `OWN_NAMES` in
  `ldap/ldap_server.js`) so that an entry is displayed as written. An
  attribute missing from that table still works, but is shown lower-cased on
  `/admin/ldap/directory`.

In [PostgreSQL](postgres-schema.md) every entry is one row of
`sts_ldap_entries`, with these attributes in the `attrs` JSONB column. With
`persistence.mode=ldif` an entry is one LDIF record.

## The tree

Each trust realm has its own tree, rooted at the RFC 2247 form of the realm's
DNS domain ([LDAP → A tree per trust realm](ldap.md#a-tree-per-trust-realm-named-by-dn)).

```
dc=example,dc=com                       domain, dcObject
├── ou=users                            people, and every identity that authenticates
├── ou=groups                           groupOfNames
├── ou=applications                     applicationProcess + stsApplication
├── ou=federations                      applicationProcess + stsFederation
├── ou=roles                            stsRole
├── ou=policies                         xacmlPolicy
├── ou=peps                             xacmlPep
├── ou=passwordPolicies                 pwdPolicy + stsPasswordPolicy
├── ou=spiffe
│   ├── ou=entries                      applicationProcess + spiffeRegistrationEntry
│   └── ou=agents                       applicationProcess + spiffeAgent
├── ou=devices                          device + stsDevice          (#130)
├── ou=oidfed                           stsOidfedEntry              (#132)
├── ou=claimproviders                   stsClaimProvider            (#147)
├── ou=trustAnchors                     stsTrustAnchor              (default realm only)
└── ou=crl                              cRLDistributionPoint        (created on first CRL)
```

Every container is `top, organizationalUnit` with a `description`. All of them
are seeded, in both modes.

## Operational attributes

| Attribute | Source | Notes |
|---|---|---|
| `entryUUID` | RFC 4530 | assigned at creation and kept through a rename. **A person's `sub` is `urn:uuid:<entryUUID>`**, and a SCIM `id` is the bare value. Returned only when asked for by name. No client can write it (`STS-LDAP-0076`) |
| `createTimestamp`, `modifyTimestamp` | RFC 4512 | generalized time. Read-only in product mode |
| `entryDN` | RFC 5020 | computed at search time; read-only in product mode |
| `stsEntryUuidAlias` | this service | the losing `entryUUID` of a two-process create race, resolved to the same entry. Protected like `entryUUID` |
| `memberOf` | computed | a person's groups, derived from `member` values, never stored |

---

## People: `ou=users`

`objectClass: top, person, organizationalPerson, inetOrgPerson`. The RDN is
`uid=<username>`. **One person is one entry**, however they arrive. An
identity that names nobody by itself (a DID, a SPIFFE ID) gets an entry
named by a digest of its identifier.

### Standard attributes

All the inetOrgPerson attributes (RFC 2798, RFC 4519) can be stored, and
`/portal` draws all fifty of them. This service reads and writes these:

| Attribute | Use |
|---|---|
| `uid`, `cn`, `sn`, `givenName`, `displayName`, `mail` | the person. In development mode an auto-created entry gets invented values; product mode invents none |
| `userPassword` | **scrypt hash** (`$scrypt$N$r$p$salt$hash`), hashed on every write including an LDAP modify. Withheld from reads in product mode |
| `userCertificate` | standard, but not what this service writes for a presented certificate (see `x509*`) |
| `title`, `employeeType`, `telephoneNumber`, `mobile`, `street`, `l`, `st`, `postalCode`, `c`, `postalAddress`, `o`, `ou`, `departmentNumber`, `employeeNumber`, `preferredLanguage`, `labeledURI`, `manager` | released as claims (`oid4vc/vc_claims.ts`) and mapped by SCIM (`scim/scim_map.ts`) |
| `schacDateOfBirth`, `schacCountryOfCitizenship`, `schacPersonalTitle` | SCHAC names, released as `birthdate`, `nationalities`, `title` |
| `salutation`, `birthFamilyName`, `birthGivenName`, `birthMiddleName`, `alsoKnownAs`, `placeOfBirthCountry`, `placeOfBirthRegion`, `placeOfBirthLocality` | this service's own, for Identity Assurance claims |
| `scimExternalId` | SCIM `externalId`, on people and groups |
| `userPrincipalName` | read by certificate enrollment's smartcard-logon profile. Nothing in the service writes it; a client supplies it |
| `pwdChangedTime`, `pwdHistory` | draft-behera password policy: when the password last changed, and earlier hashes for the history rule |
| `pwdReset` | draft-behera: the password must be changed at the next sign-in |
| `pwdAccountLockedTime` | draft-behera. **The account is disabled** while this is set (`000001010000Z` means an administrator disabled it), and every door refuses the person. `common/account_state.ts` is the only writer |

### Credentials

| Attribute | What it holds | Protection |
|---|---|---|
| `stsWebauthnCredential` | registered WebAuthn public keys | public by design |
| `stsTotpCredential` | the RFC 6238 shared secret | **sealed** under the key-encryption key in product mode. Withheld from reads |
| `stsBackupCodes` | JSON: each code's scrypt hash and `usedAt`, plus counts | hashed per code (older sealed sets are still read). The comment in `OWN_NAMES` saying "encrypted" is out of date |
| `stsAppPassword` | JSON per app password: name, the doors it is scoped to, scrypt hash, last use (#101) | withheld |
| `stsActivationToken`, `stsActivationExpires` | an activation link's hash and expiry | hashed |
| `stsPasswordResetToken`, `stsPasswordResetExpires` | a reset link's hash and expiry | withheld |
| `stsKrb5Keys`, `stsKrb5KeyInfo` | Kerberos long-term keys for every enctype, derived from the password, and their public half (kvno, enctypes, when) | keys **sealed and withheld**, including the ciphertext |
| `hobaPublicKey` | RFC 7486 HOBA keys, `<kid> <base64 DER>` | public |
| `stsSelfIssuedSubject` | SIOPv2 subjects the person enrolled (a DID or a JWK thumbprint URI), as JSON (#129) | withheld |
| `stsCibaUserCode` | the CIBA user code the person set on `/portal/ciba` (#131) | scrypt-hashed, withheld |
| `stsAudSub` | the account id a client knows the person by, `<client_id> <aud_sub>` per value, sent as that client's ID Token `aud_sub` (#148) | plain |
| `stsClaimSourceTokens` | the person's access and refresh tokens at each Claims Provider they linked on `/portal/claim-sources`, one JSON value (#147) | **sealed** where keys persist, withheld |

### Assertion key pairs (RFC 7523 and RFC 7522)

A person may hold a key pair to sign assertions **about themselves only**. The
two sets share no names.

| JWT (RFC 7523) | SAML (RFC 7522) |
|---|---|
| `stsAssertionIssuer` | `stsSamlAssertionIssuer` |
| `stsAssertionJwks`, `stsAssertionKid` | `stsSamlAssertionThumbprint` |
| `stsAssertionCertificate`, `stsAssertionCertificateChain` | `stsSamlAssertionCertificate`, `stsSamlAssertionCertificateChain` |
| `stsAssertionPrivateKey` (**sealed, withheld**) | `stsSamlAssertionPrivateKey` (**sealed**) |
| `stsAssertionExpiresAt`, `stsAssertionKeySource` | `stsSamlAssertionExpiresAt`, `stsSamlAssertionKeySource` |

`…KeySource` says whether the pair was issued here or a certificate was
uploaded instead.

### Certificates issued by enrollment (ACME, EST, SCEP)

`common/cert_enrollment.ts` keeps every certificate on the entry it names.

| Attribute | Notes |
|---|---|
| `stsEnrolledCertificate` | public |
| `stsEnrolledPrivateKey` | present only when this service generated the key (EST `/serverkeygen`). **Withheld** |
| `stsAcmeEabKey` | the ACME External Account Binding key. **Withheld** |
| `stsScepChallenge` | a single-use SCEP challenge password. **Withheld** |
| `stsCertificateHostName` | host names an administrator registered for this entry |

### What this service learned about the person

| Attribute | Meaning |
|---|---|
| `authnMethod`, `mfaAuthenticated`, `mfaLastAuthTime` | how they last authenticated, where the protocol said. `mfaLastAuthTime` is never cleared |
| `x509subject`, `x509issuer`, `x509serialNumber`, `x509notBefore`, `x509notAfter`, `x509fingerprint256` | a verified client certificate, or an issued X509-SVID |
| `x509svidsIssued`, `x509firstIssued`, `x509lastIssued` | X509-SVIDs only: how many have been issued, and since when |
| `didSubject`, `didMethod` | the DID this entry is. The entry is found by `didSubject` |
| `spiffeSubject`, `spiffePath`, `spiffeTrustDomain` | the SPIFFE ID that authenticated. **These are not the same as `spiffeId`** on a registration entry |
| `spiffeCredentialStatus`, `spiffeCredentialStatusReason`, `spiffeRevokedAt` | whether this identity may still be **issued** an SVID. This is not a certificate status |
| `federationRelationship`, `federationIssuer`, `federationLastSeen` | where a federated person came from |
| `federationLink` | `<relationship> <issuer> <subject>`: **the one that decides anything**, linking a partner's subject to this person (#109) |
| `federationAttribute` | which of the entry's other attributes came from a partner's assertion |
| `oauthConsent` | `<time> <scope> <client_id>`, one value per (application, scope) |
| `oauthConsentWithdrawn` | `<time> <scope> <client_id>` (#172). It stops a re-consent from reviving an older refresh token |
| `stsIdaVerification` | OpenID Connect for Identity Assurance verifications as JSON (#127). **Withheld**, because evidence carries document numbers |

### Flags an administrator or a flow sets

| Attribute | Meaning |
|---|---|
| `stsMfaRequired` | a second factor is required of this person |
| `stsBootstrapAdministrator`, `stsConsoleClaimedAt` | the bootstrap `admin`, and when it first claimed the console |
| `stsNotDelegated` | sensitive and cannot be delegated (Kerberos's NOT_DELEGATED) (#108) |
| `stsMayAct` | the one party this person named as a delegate. It becomes `may_act` in their access tokens |
| `stsMailVerified` | the address they proved they receive mail at (#63) |
| `stsMailVerifyToken`, `stsMailVerifyExpires`, `stsMailVerifyAddress` | a pending verification link. The token is **withheld** |

---

## Groups: `ou=groups`

`objectClass: top, groupOfNames`, with `cn`, `member` (DNs) and `description`.
Referential integrity is not enforced: deleting a person leaves their DN in
`member`. **A group grants nothing by being a group.** It grants only what a
roster or a role names it for:

| Group | Grants |
|---|---|
| `cn=admin-read` | the console and `/admin-api` read role |
| `cn=admin-write` | the console and `/admin-api` write role |
| `cn=remote-peps` | `REMOTE_PEPS`: `/xacml/pep/*` and `POST /xacml/pip` |
| `cn=xacml-users` | `XACML_USER`: the XACML PDP and policy surfaces |

The console groups are created on first grant, and the bootstrap `admin` holds both. `remote-peps` and `xacml-users` are seeded, empty in product mode. In development, demo data adds `cn=developers` and `cn=directory-admins` (which grant nothing), the people `alice`, `bob` and `carol`, and `cn=admin,<base>`.

The names are the defaults of `admin.readGroup`, `admin.writeGroup`, `roles.remotePepGroup` and `roles.xacmlUserGroup`. The directory also treats `groupOfUniqueNames`, `posixGroup` and `groupOfURLs` entries as groups, and reads `uniqueMember` and `memberUid` as well as `member`.

## Applications: `ou=applications`

`objectClass: top, applicationProcess, stsApplication`. One entry per client,
relying party, service provider, Kerberos service or GNAP client. **Nothing
caches this registry**: an `ldapmodify` takes effect on the next request.
`common/applications.js` holds the field table, and `/admin/applications`
draws it with a description of every field.

| Group | Attributes |
|---|---|
| Identity and observation | `appIdentifier`, `cn`, `appName`, `description`, `appHomePageUrl`, `appKind`, `appProtocol`, `appAllowedProtocol`, `appAuthorizationServer`, `appCorsOrigin`, `appRegistered`, `appRegisteredBy`, `appFirstSeen`, `appLastSeen`, `appAuthentications`, `appSessions`, `appUsers`, `appLastSession`, `appLastUser`, `appRedirectUriObserved`, `appReturnAddressObserved`, `appRegistrationJson`, `appRegistrationAccessToken` |
| OAuth client | `oauthClientId`, `oauthConfidential`, `oauthClientSecret` (**withheld**), `oauthClientSecretPrevious`, `oauthClientSecretPreviousUntil`, `oauthClientSecretExpiresAt`, `oauthTokenEndpointAuthMethod`, `oauthTokenEndpointAuthSigningAlg`, `oauthJwks`, `oauthJwksUri`, `oauthRedirectUri`, `oauthGrantType`, `oauthResponseType`, `oauthScope`, `oauthAllowedScope`, `oauthAudience`, `oauthSubjectType`, `oauthSectorIdentifierUri` |
| Logout | `oauthPostLogoutRedirectUri`, `oauthFrontchannelLogoutUri`, `oauthFrontchannelLogoutSessionRequired`, `oauthBackchannelLogoutUri`, `oauthBackchannelLogoutSessionRequired`, `oauthRevokeRefreshOnLogout` |
| Requests and responses | `oauthRequestUri`, `oauthRequestObjectSigningAlg`, `oauthRequestObjectEncryptionAlg`, `oauthRequestObjectEncryptionEnc`, `oauthRequireSignedRequestObject`, `oauthRequirePushedAuthorizationRequests`, `oauthIntrospectionSignedResponseAlg`, `oauthIntrospectionEncryptedResponseAlg`, `oauthIntrospectionEncryptedResponseEnc`, `oauthAuthorizationDetailsType`, `oauthAuthorizationDetailsTypes`, `oauthStepUpAcrValues`, `oauthStepUpMaxAge` |
| Resource server and consent | `oauthPermissionBaseUri`, `oauthPermission`, `oauthDelegatedPermission`, `oauthResourceMetadata`, `oauthResourceMetadataUrl`, `oauthGlobalConsent`, `oauthGlobalConsentWithdrawn` |
| Token lifetimes | `oauthAccessTokenTtlS`, `oauthIdTokenTtlS`, `oauthRefreshTokenTtlS`, `oauthRefreshIdleSeconds`, `oauthTokenExchangeRefreshToken` |
| Mutual TLS (RFC 8705) | `oauthTlsClientAuthSubjectDn`, `oauthTlsClientAuthSanDns`, `oauthTlsClientAuthSanUri`, `oauthTlsClientAuthSanIp`, `oauthTlsClientAuthSanEmail`, `oauthTlsClientCertificateBoundAccessTokens`, `oauthTlsClientCertificateThumbprint` |
| JWT assertion key pair (RFC 7523) | `oauthAssertionIssuer`, `oauthAssertionJwks`, `oauthAssertionKid`, `oauthAssertionCertificate`, `oauthAssertionCertificateChain`, `oauthAssertionPrivateKey` (**withheld**), `oauthAssertionExpiresAt`, `oauthAssertionKeySource` |
| SAML assertion key pair (RFC 7522) | `oauthSamlAssertionIssuer`, `oauthSamlAssertionSigningCertificate`, `oauthSamlAssertionCertificate`, `oauthSamlAssertionCertificateChain`, `oauthSamlAssertionPrivateKey`, `oauthSamlAssertionThumbprint`, `oauthSamlAssertionExpiresAt`, `oauthSamlAssertionKeySource` |
| Software statements (RFC 7591) | `oauthSoftwareStatementIssuer`, `oauthIssuedSoftwareStatement`, `appSoftwareStatementIssuer`, `appSoftwareStatementTrusted`, `appSoftwareStatementPublisher` |
| OpenID Provider Commands (#151) | `oauthCommandEndpoint` (https, no fragment: where a Command Token is POSTed) |
| CIBA (#131) | `oauthBackchannelTokenDeliveryMode` (`poll`, `ping` or `push`), `oauthBackchannelClientNotificationEndpoint` (https, for ping and push), `oauthBackchannelAuthenticationRequestSigningAlg` (an asymmetric alg: every request signed), `oauthBackchannelUserCodeParameter` (TRUE: every request carries the person's user code) |
| Native SSO (#130) | `oauthNativeSso` (TRUE lets the client ask for `device_sso`), `oauthNativeSsoGroup` (the apps that may share one device session). Settable by a registration only through a trusted software statement |
| SAML service provider | `samlEntityId`, `samlAssertionConsumerService`, `samlSingleLogoutService`, `samlNameIdFormat`, `samlResponseBinding`, `samlSigningCertificate`, `samlObservedSigningCertificate`, `samlEncryptionCertificate`, `samlAuthnRequestVerification`, `samlAuthnRequestSigned`, and from consumed metadata: `samlSpMetadataUrl`, `samlSpMetadata`, `samlAcsEndpoint`, `samlSloEndpoint`, `samlSpNameIdFormat`, `samlSpAuthnRequestsSigned`, `samlSpWantAssertionsSigned`, `samlSpWantAssertionsEncrypted`, `samlSpMetadataValidUntil`, `samlSpMetadataCacheDuration`, `samlSpMetadataConsumedAt`, `samlSpMetadataSignature`, `samlSpMetadataSigningCertificate` |
| SAML per-profile | `saml2AssertionLifetimeMin`, `saml2SignAssertion`, `saml2SignResponse`, `saml2NameIdFormat`, `saml2ArtifactTtlS`, `saml2EncryptAssertion`, `saml2EncryptionAlgorithm`, `saml2KeyTransportAlgorithm`, `saml2EncryptLogoutNameId`, `saml11AssertionLifetimeMin`, `saml11SignAssertion`, `saml11SignResponse`, `saml11NameIdFormat`, `saml11ArtifactTtlS` |
| WS-* | `wsfedRealm`, `wsfedReplyUrl`, `wsfedSignOutUri`, `wsfedAssertionLifetimeMin`, `wstrustAppliesTo` |
| Kerberos service | `krb5ServicePrincipalName`, `krb5ServiceKeys` (**sealed**), `krb5ServiceKeyInfo` |
| Delegation (#108) | `appAllowedToDelegateTo`, `appAllowedToActOnBehalfOf`, `appDelegationSubjectGroup`, `appTrustedToImpersonate` |
| Roles and claims | `appRequiredRole`, `appGroupsClaim`, `appGroupsClaimName`, `appGroupsClaimValue`, `appGroupsClaimFromMemberOf`, `appAuthnMechanism` |
| Certificate enrollment | `appEnrolledCertificate`, `appEnrolledPrivateKey`, `appAcmeEabKey`, `appScepChallenge`, `appCertificateHostName` |
| GNAP | `gnapInstanceId`, `gnapClassId`, `gnapKey`, `gnapKeyIdentity`, `gnapKeyReference`, `gnapKeyProof`, `gnapMtlsTrust`, `gnapSymmetricKey` (**withheld**), `gnapSymmetricAlg`, `gnapDisplayUri`, `gnapLogoUri`, `gnapFinishUri`, `gnapInteractionStartModes`, `gnapAllowedAccess`, `gnapBearerTokens`, `gnapSkipInteraction`, `gnapAccessTokenFormat`, `gnapAccessTokenLifetimeS`, `gnapResourceServerUri`, `gnapJweKey`, `gnapMacaroonKey`, `gnapScopedSignals` |
| Links to other registries | `oid4vpClientId`, `federationPartnerId`, `appFederationRelationship`, `appFederationAutoRedirect`, `ldapBindDn`, `scimClientId`, `ssfReceiverId`, `ssfDeliveryEndpoint`, `ssfAllowedEvents`, `spiffeWorkloadId` |

## Federation relationships: `ou=federations`

`objectClass: top, applicationProcess, stsFederation`. Each relationship is
**created disabled**, and changing one is a security change: see
[federation](federation.md). `federation/federation.js` holds the schema, and
`/admin/ldap/federations` publishes it.

| Group | Attributes |
|---|---|
| Identity | `fedId`, `fedName`, `fedEnabled`, `fedProtocol`, `fedRole`, `fedPeer`, `fedLocalEntityId`, `fedApplication`, `fedApplicationUse` |
| Endpoints | `fedSsoUrl`, `fedSloUrl`, `fedSloBinding`, `fedBinding`, `fedTokenUrl`, `fedUserinfoUrl`, `fedEndSessionUrl`, `fedJwksUri` |
| Keys | `fedSigningCertificate` (**decides whose assertions are believed**), `fedJwks`, `fedEncryptionKey` (**withheld**), `fedEncryptionKeyType`, `fedKeyManagementAlgorithm`, `fedContentEncryptionAlgorithm`, `fedSignRequest` |
| OIDC as client | `fedClientId`, `fedClientSecret` (**withheld**), `fedScope`, `fedResponseType` |
| Policy | `fedAllowUnsolicited`, `fedAllowUnencrypted`, `fedAcceptSignout`, `fedRequireSignedLogout`, `fedMayAssertAdministrators`, `fedAuthnMechanism`, `fedAuthnRelationship` |
| Subjects and provisioning | `fedSubjectPolicy`, `fedSubjectPattern`, `fedSubjectDomain`, `fedSubjectGroup`, `fedHomeRealmDomain` (#148, the domains whose `domain_hint` goes to this partner), `fedUsernameSource`, `fedAutocreateUsers`, `fedUpdateUserAttributes`, `fedAttributeMap`, `fedRelease` |
| Observation | `fedFirstSeen`, `fedLastSeen`, `fedLastUser`, `fedUsers`, `fedAuthentications`, `fedLastError`, `fedLastErrorAt` |

## Roles: `ou=roles`

`objectClass: top, stsRole`, named `cn=<role>`, with `roleName`, `description` and the three kinds of
holder: `roleMemberUser`, `roleMemberGroup` and `roleMemberApplication`. A role saved by an earlier version was written with
no object class and gains one on its next save.
`common/roles.js` keeps apart who **holds** a role and what **requires** one
(`appRequiredRole` on an application). It also computes ten built-in roles that are not stored: EVERYBODY, ALL_AUTHENTICATED_USERS, ALL_UNAUTHENTICATED_USERS, ALL_APPLICATIONS, ALL_AUTHENTICATED_APPLICATIONS, ALL_UNAUTHENTICATED_APPLICATIONS, ADMIN_READ, ADMIN_WRITE, REMOTE_PEPS and XACML_USER.

## XACML: `ou=policies` and `ou=peps`

`ou=policies` is the policy repository itself, not a copy of it
(`xacml/xacml_store.ts`). `objectClass: top, xacmlPolicy`, with
`xacmlPolicyId`, `xacmlVersion`, `xacmlKind` (policy or policy set),
`xacmlCombiningAlgId`, `xacmlPolicyDocument` (the XACML XML), `xacmlPolicy`,
`xacmlEnabled`, `xacmlIsRoot` and `xacmlDetail`.

`ou=peps` holds the remote PEPs (`xacml/xacml_pep_registry.ts`).
`objectClass: top, xacmlPep`, with `xacmlPepIdentity`, `xacmlPepEnabled`,
`xacmlPepCertificateSubject`, `xacmlPepThumbprint`, `xacmlPepBias`,
`xacmlPepResource`, `xacmlPepNotifyUrl`, `xacmlPepVersion`,
`xacmlPepRegisteredAt`, `xacmlPepLastSeen`, `xacmlPepLastNotify`,
`xacmlPepSyncToken`, `xacmlPepPolicyCount`, and the counters
`xacmlPepDecisions`, `xacmlPepAllowed`, `xacmlPepRefused`,
`xacmlPepAuthenticated` and `xacmlPepUndischargeable`. See
[remote PEP](remote-pep.md).

## Password policies: `ou=passwordPolicies`

`objectClass: top, pwdPolicy, stsPasswordPolicy`. The draft-behera attributes
`pwdAttribute`, `pwdMinLength` and `pwdInHistory` sit beside this service's
`stsPwd*` attributes (`stsPwdRequireUppercase`, `stsPwdRequireDigit`,
`stsPwdMinSymbols`, `stsPwdGeneratedLength` and others), which cover the
composition rules and the generator. The default profile is **not seeded**:
the defaults apply until an administrator saves one. See `common/password_policy.ts`.

## SPIFFE: `ou=spiffe`

The registry is kept in the directory (`spiffe/spiffe_registry.ts`).

**Registration entries** (`ou=entries`, `objectClass: top, applicationProcess, spiffeRegistrationEntry`):
`spiffeEntryId`, `spiffeId`, `spiffeParentId`, `spiffeSelector`,
`spiffeX509SvidTtl`, `spiffeJwtSvidTtl`, `spiffeDnsName`, `spiffeFederatesWith`,
`spiffeAdmin`, `spiffeDownstream`, `spiffeHint`, `spiffeStoreSvid`,
`spiffeEntryExpiresAt`, `spiffeRevisionNumber`, `spiffeCreatedAt`,
`spiffeOrigin`, `spiffeSvidsIssued`, `spiffeLastSvidAt`.

**Attested agents** (`ou=agents`, `cn=agent-<12 hex>`, `objectClass: top, applicationProcess, spiffeAgent`): `spiffeAgentId`,
`spiffeAttestationType`, `spiffeAgentSelector`, `spiffeAgentSvidHash`,
`spiffeAgentExpiresAt`, `spiffeAgentBanned`, `spiffeAgentCanReattest`,
`spiffeAttestations`, `spiffeFirstSeen`, `spiffeLastSeen`.

Deleting an entry, or banning or deleting an agent, sets
`spiffeCredentialStatus` on the affected people in `ou=users`.

## Devices: `ou=devices` (#130)

Made by OpenID Connect Native SSO for Mobile Apps 1.0
([OAuth 2.0 and OpenID Connect](oauth-oidc.md)). It is the foundation of #164, which will add a
device's keys and compliance state to the same entries. People see theirs on
`/portal/devices`; administrators on the person's page and at
`GET /admin-api/users/devices`.

A device (the phone or laptop a person's apps run on) is an entry of its own
rather than a field on the person. The DN is `cn=<uuid>,ou=devices,<base>`, and
`common/devices.ts` owns what an entry means.

| Attribute | Meaning |
|---|---|
| `objectClass` | `top, device` (RFC 4519 §3.4), `stsDevice` |
| `cn` | the device id, a UUID this service assigned |
| `owner` | the DN of the person whose device it is (RFC 4519) |
| `description` | what to call it on a page |
| `stsDeviceApplication` | the DN of every application that has used it |
| `stsDeviceSecretHash` | SHA-256 of its Native SSO `device_secret`. **Withheld from every read** |
| `stsDeviceSession` | the sign-on session the secret is good for. The secret is accepted only while that session is live |
| `stsDeviceLastUsed` | ISO 8601 |

The secret is never rotated, because every app on the device shares it. A new
sign-in that presents the secret re-binds the same device to the new session.
One person holds at most `oauth2.maxDevicesPerPerson` devices; at that limit
the least recently used device whose session has ended is replaced (or, if
none has ended, the least recently used one).

## OpenID Federation: `ou=oidfed` (#132, #136, #137)

The realm's register as an OpenID Federation entity
([OpenID Federation](oidfed.md)). Every entry is of class `stsOidfedEntry`
and is named `cn=<prefix><digest>`, where the digest is SHA-256 of what the
entry is about (hex, 32 characters). `oidfed/oidfed_store.ts` owns what an
entry means.

| Attribute | Meaning |
|---|---|
| `objectClass` | `top`, `stsOidfedEntry` |
| `stsOidfedKind` | `keys`, `subordinate` (`sub-`), `anchor` (`ta-`), `mark-type` (`mt-`), `issued-mark` (`im-`), `held-mark` (`hm-`), `mark-policy` (`mp-`), `events` (`ev-`, #137), `suspension` (`su-`, #137) or `collection` (the one `cn=collection` entry, #136) |
| `stsOidfedEntityId` | the Entity Identifier the entry is about |
| `stsOidfedData` | the record, as one JSON value: a subordinate's keys, metadata, metadata policy and constraints; an anchor's pinned keys; a mark and its status; a suspension's time, reason and page; the last Entity Collection crawl. An `events` or `suspension` entry about a realm of this service is keyed `realm:<id>` rather than by identifier |
| `stsOidfedEvent` | on an `events` entry: one subordinate's history, one JSON event per value (`iat`, `event`, and `event_description` and `information_uri` where given). Appended and never rewritten, and merged by value when two nodes write at once. The entry outlives the subordinate |
| `stsOidfedKeys` | on the one `cn=keys` entry: the realm's Federation Entity Key table, one JSON row per value, each private key **sealed** where keys persist. **Withheld from every read**, and each row's private key is replaced by a placeholder in searches and in the directory dump |

## Claims Providers: `ou=claimproviders` (#147)

The OpenID Providers this realm fetches aggregated or distributed claims from
([OpenID Connect](oauth-oidc.md)). One entry per provider, named `cn=<id>`;
`oauth-oidc/claims_providers.ts` owns what an entry means.

| Attribute | Meaning |
|---|---|
| `objectClass` | `top`, `stsClaimProvider` |
| `stsClaimProviderData` | the provider, as one JSON value: its id and name, issuer, authorization, token, claims and JWKS endpoints, this realm's client id and authentication method there, the scope asked for, the claims it supplies, and `aggregated` or `distributed` |
| `stsClaimProviderSecret` | this realm's client secret at the provider. **Sealed** where keys persist, and **withheld from every read** |

## Trust anchors and CRLs

`ou=trustAnchors` exists only in the default realm, with one
`objectClass: top, stsTrustAnchor` entry per CA trusted for client
certificates: `stsTrustAnchor`, `stsTrustAnchorCertificate`,
`stsTrustAnchorFingerprint`, `stsTrustAnchorAddedBy`. A certificate is public,
so none of these is sealed. An entry here decides whose client certificate
becomes an identity. See [TLS](tls.md).

`ou=crl` holds `objectClass: top, cRLDistributionPoint` entries (`cn=<caId>`, `certificateRevocationList;binary`) once a CRL is published. They are a cache of the register, readable anonymously ([PKI](pki.md)).

---

## What an LDAP read never returns

**In product mode** (`mode.withholdsDirectorySecrets()`), these attributes are
withheld from every search result, filter and compare, administrators
included (`SECRET_ATTRIBUTES` in `ldap/ldap_server.js`):

* passwords: `userPassword`, `pwdHistory`, `stsAppPassword`,
  `stsActivationToken`, `stsPasswordResetToken`, `stsMailVerifyToken`
* second factors and subjects: `stsTotpCredential`, `stsBackupCodes`,
  `stsSelfIssuedSubject`, `stsIdaVerification`, `stsCibaUserCode`
* devices: `stsDeviceSecretHash`
* client secrets: `oauthClientSecret`, `appRegistrationAccessToken`,
  `fedClientSecret`, `stsClaimProviderSecret`
* tokens held for a person at another provider: `stsClaimSourceTokens`
* private keys: `oauthAssertionPrivateKey`, `oauthSamlAssertionPrivateKey`,
  `stsAssertionPrivateKey`, `stsSamlAssertionPrivateKey`,
  `stsEnrolledPrivateKey`, `appEnrolledPrivateKey`, `fedEncryptionKey`
* enrollment credentials: `stsAcmeEabKey`, `appAcmeEabKey`, `stsScepChallenge`,
  `appScepChallenge`
* Kerberos and GNAP keys: `stsKrb5Keys`, `krb5ServiceKeys`, `gnapSymmetricKey`,
  `gnapMacaroonKey`
* devices: `stsDeviceSecretHash` (from #130)
* the Federation Entity Key table: `stsOidfedKeys` (from #132)

**Some are withheld in every mode**, replaced by a placeholder in searches and
in the directory dump: the certificate-enrollment secrets, the Kerberos keys,
and the private key inside each `fedEncryptionKey` row and each
`stsOidfedKeys` row.

**Hashed** (scrypt): `userPassword`, `pwdHistory`, the activation, reset and
mail-verification tokens, each recovery code and each app password.
`stsScepChallenge` holds a SHA-256 digest. **Sealed** (`$aesgcm$1$…` under the
key-encryption key, in product; clear in development): the TOTP secret,
`stsKrb5Keys`, `krb5ServiceKeys`, every RFC 7523 and RFC 7522 private key, the
EAB keys, enrolled private keys and `fedEncryptionKey` private keys.
`oauthClientSecret` is withheld but stored in the clear.
[Encryption at rest](encryption-at-rest.md) has the rest.

`pwdHistory` and `pwdChangedTime` are maintained by the service and refused on
an LDAP write. Product refuses a pre-hashed `$scrypt$` `userPassword`.

In product mode, what a bound identity may read and write is decided per
identity, and only a person may bind: see
[LDAP → What a bound identity may read](ldap.md#what-a-bound-identity-may-read-product-mode).

## Keeping this page current

This page is a copy of tables that live in code, so it can drift. The sources:

* `ldap/ldap_server.js`: `STANDARD_NAMES`, `OWN_NAMES`, `SECRET_ATTRIBUTES`,
  and `seed()` for the containers
* `common/applications.js`: the application field table
* `federation/federation.js`, `spiffe/spiffe_registry.ts`,
  `xacml/xacml_store.ts`, `xacml/xacml_pep_registry.ts`, `common/roles.js`,
  `common/password_policy.ts`, `common/devices.ts`

A running service describes its own containers: `/admin/ldap/directory` shows
any entry, and `/admin/ldap/federations` shows the federation schema.

## Related

* [LDAP](ldap.md): the protocol, the sockets, the five rules and the settings.
* [PostgreSQL schema](postgres-schema.md): where these entries are stored.
* [SCIM 2.0](scim.md): how SCIM attributes map onto these.
