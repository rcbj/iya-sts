// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/names.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of the directory's name lists.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// The canonical spellings the directory folds a name to, and the attributes it
// withholds from every reader. `ldap/ldap_server.js` reads these from what the
// image build generates. The comments are the ones that sat on these lists there.

@spellings(#{
  standard: #[
  // RFC 4519 — the standard directory attribute types, in full. `name` is in
  // here because it is a real type (section 2.18): the supertype cn, sn, ou and
  // the rest derive from, which a client may perfectly well ask for by name.
  "businessCategory", "c", "cn", "dc", "description", "destinationIndicator",
  "distinguishedName", "dnQualifier", "enhancedSearchGuide",
  "facsimileTelephoneNumber", "generationQualifier", "givenName",
  "houseIdentifier", "initials", "internationalISDNNumber", "l", "member",
  "name", "o", "ou", "owner", "physicalDeliveryOfficeName", "postalAddress",
  "postalCode", "postOfficeBox", "preferredDeliveryMethod", "registeredAddress",
  "roleOccupant", "searchGuide", "seeAlso", "serialNumber", "sn", "st",
  "street", "telephoneNumber", "teletexTerminalIdentifier", "telexNumber",
  "title", "uid", "uniqueMember", "userPassword", "x121Address",
  // RFC 4519 section 2.40 spells this with a lower-case x, and RFC 2798's
  // inetOrgPerson definition spells the same type `x500uniqueIdentifier`. The
  // registered directory-schema spelling wins here; the two differ only in a
  // letter LDAP does not distinguish anyway, so nothing matches differently —
  // one of them just has to be chosen for the display.
  "x500UniqueIdentifier",

  // RFC 4524 — COSINE. The types still in ordinary use; the specification also
  // carries a dozen marked obsolete or historic (janetMailbox, dITRedirect,
  // the three *Quality types) and those are deliberately left out rather than
  // listed, since publishing a spelling suggests the name is worth writing.
  "associatedDomain", "associatedName", "buildingName", "co", "documentAuthor",
  "documentIdentifier", "documentLocation", "documentPublisher",
  "documentTitle", "documentVersion", "drink", "homePhone", "homePostalAddress",
  "host", "info", "mail", "manager", "organizationalStatus", "otherMailbox",
  "personalTitle", "roomNumber", "secretary", "uniqueIdentifier", "userClass",

  // RFC 2798 — inetOrgPerson, which is the class most of the people in this
  // directory would carry in a real one. `labeledURI` is RFC 2079's rather than
  // this one's; it is grouped here because inetOrgPerson is where it is met.
  "audio", "carLicense", "departmentNumber", "displayName", "employeeNumber",
  "employeeType", "jpegPhoto", "labeledURI", "mobile", "pager", "photo",
  "preferredLanguage", "userCertificate", "userPKCS12", "userSMIMECertificate",

  // RFC 4523 — the PKI types. `certificateRevocationList` is the one this
  // service WRITES, on every `cRLDistributionPoint` entry under `ou=crl`, and
  // it was coming back as `certificaterevocationlist;binary` to a client
  // reading the distribution point a certificate named.
  "authorityRevocationList", "cACertificate", "certificateRevocationList",
  "crossCertificatePair", "deltaRevocationList", "supportedAlgorithms",

  // RFC 2307 — NIS. `memberUid` is the one that earns its place beyond the
  // display: it holds a BARE USER NAME where member and uniqueMember hold a DN,
  // which is why /admin/groups resolves it differently — see MEMBER_ATTRIBUTES.
  "bootFile", "bootParameter", "gecos", "gidNumber", "homeDirectory",
  "ipHostNumber", "ipNetmaskNumber", "ipNetworkNumber", "ipProtocolNumber",
  "ipServicePort", "ipServiceProtocol", "loginShell", "macAddress",
  "memberNisNetgroup", "memberUid", "nisMapEntry", "nisMapName",
  "nisNetgroupTriple", "oncRpcNumber", "shadowExpire", "shadowFlag",
  "shadowInactive", "shadowLastChange", "shadowMax", "shadowMin",
  "shadowWarning", "uidNumber",

  // RFC 4512 — the object class attribute, the operational attributes every
  // entry has, and the subschema ones. A SEARCH withholds the operational ones
  // unless they are asked for by name (section 4.5.1.8) and toSearchEntry()
  // honours that; being withheld is no reason to be unable to spell them, since
  // asking for one by name is exactly when a client sees it.
  "aliasedObjectName", "attributeTypes", "createTimestamp", "creatorsName",
  "dITContentRules", "dITStructureRules", "governingStructureRule",
  "ldapSyntaxes", "matchingRules", "matchingRuleUse", "modifiersName",
  "modifyTimestamp", "nameForms", "objectClass", "objectClasses",
  "structuralObjectClass", "subschemaSubentry",

  // RFC 4512 again — the root DSE's own attributes (section 5.1), plus the two
  // vendor ones from RFC 3045. They are here for the same reason as the rest: a
  // client showing `namingcontexts` where every document says `namingContexts`
  // looks like the client is broken.
  "altServer", "namingContexts", "supportedControl", "supportedExtension",
  "supportedFeatures", "supportedLDAPVersion", "supportedSASLMechanisms",
  "vendorName", "vendorVersion",

  // RFC 5020 and RFC 4530 — the two operational attributes that name an entry
  // rather than describe it. `entryDN` is load-bearing beyond the display: it
  // is what matchable() calls the DN when a filter matches on it, and what
  // entryObject() publishes the DN as, so those two and this table have to
  // agree or an ldapsearch filter and a console page name one fact two things.
  "entryDN", "entryUUID",

  // PKCS#9, and it arrives on this directory inside a certificate subject —
  // certificatePlan() turns every RDN of a verified client certificate's
  // subject into an attribute, so which types turn up is decided by whoever
  // issued the certificate and not by anything here.
  "emailAddress",

  // NOT REGISTERED ANYWHERE, and here anyway. `memberOf` is the reverse of
  // group membership as Active Directory and most directories in the wild
  // implement it, and it has never been standardised —
  // draft-ietf-ldapext-memberof expired. It cannot go in this service's own
  // list either, because this service did not invent it: a client writes it,
  // and /admin/groups reports the disagreement when an entry's own memberOf
  // names a group that does not list it back. NOTHING HERE MAINTAINS IT — that
  // page says so, and the spelling being conventional must not be read as the
  // attribute being managed.
  "memberOf"
],
  own: #[
  // On the entries a TLS client certificate seeds. There is no standard
  // attribute type for "the DN inside the certificate", and the standard one
  // that does exist — `userCertificate`, which is binary — is not what these
  // are; certificatePlan() says the rest.
  "x509subject", "x509issuer", "x509serialNumber", "x509notBefore",
  "x509notAfter", "x509fingerprint256",

  // THE SAME SIX ARE NOW ALSO WRITTEN BY THE SPIFFE ISSUING AUTHORITY, onto the
  // entry of every identity it mints an X509-SVID for — the same names on
  // purpose, because a certificate is a certificate however it arrived and a
  // second set spelt `svid*` would mean a filter written for one path silently
  // misses the other. The three below go with them and exist only on that path:
  // an SVID is minted afresh every half-lifetime, so the six above are ASSIGNED
  // rather than appended there and these are what is left to say how many times
  // and since when. See applySpiffeCertificate().
  "x509svidsIssued", "x509firstIssued", "x509lastIssued",

  // On the entries a DECENTRALIZED IDENTIFIER seeds, and load-bearing rather
  // than decorative: the entry is NAMED by a hash of the DID (didPlan() says
  // why), so `didSubject` is the only place the identifier itself survives and
  // the only thing locateEntry() can find the entry by. There is no standard
  // attribute type for "the DID this entry is", which is unsurprising — DID
  // Core postdates the LDAP schema documents by two decades and nobody
  // registered one.
  "didSubject", "didMethod",

  // On the entries a SPIFFE identity seeds, and load-bearing for exactly the
  // reason the two above it are: the entry is NAMED by a hash of the SPIFFE ID
  // (spiffePlan() says why), so `spiffeSubject` is the only place the
  // identifier itself survives and the only thing locateEntry() can find the
  // entry by. `spiffePath` and `spiffeTrustDomain` are the two halves of it a
  // reader actually wants to filter on. Note that these are DIFFERENT NAMES
  // from `spiffeId` and `spiffeAgentId` one container over: those are on
  // REGISTRATION entries under ou=spiffe and mean "the identity this entry
  // configures", where these are on a PERSON under ou=users and mean "an
  // identity that authenticated here". Merging the two spellings would file a
  // registration entry and its holder under one name.
  "spiffeSubject", "spiffePath", "spiffeTrustDomain",

  // WHETHER THIS IDENTITY MAY STILL BE ISSUED A CREDENTIAL HERE, and this is
  // the one group in this list whose name could be read as a claim the service
  // does not make. **SPIFFE HAS NO REVOCATION** — `GET /spiffe` says so, and
  // the Workload API's `crl` field is empty because empty is the conforming
  // value, not because it is unimplemented. `spiffeCredentialStatus` is NOT a
  // certificate status and nothing verifying an SVID consults it: it records
  // the three things in the registry that end an identity's ability to get a
  // NEW one — its registration entry deleted, its agent banned, its agent
  // deleted — and the certificates already in the world go on verifying until
  // they expire, exactly as SPIFFE intends. The reason is a sentence rather
  // than a code because it is the only thing that explains a status a reader
  // did not expect. `spiffeRevokedAt` is never cleared, which is
  // `mfaLastAuthTime`'s rule: it is the history the current-state flag beside
  // it deliberately does not keep.
  "spiffeCredentialStatus", "spiffeCredentialStatusReason", "spiffeRevokedAt",

  // On any entry whose person authenticated somewhere that STATES how they did
  // it — which today is the sign-in screen and nothing else, because amr is an
  // OIDC vocabulary and a Kerberos AS-REQ has nothing to put in it. There is no
  // standard attribute type for "this account authenticated with more than one
  // factor": the nearest things in the wild are Active Directory's msDS-*
  // attributes, which are Microsoft's own names for something else entirely,
  // and pretending to be one of those would be worse than obviously not being
  // one.
  "authnMethod", "mfaAuthenticated", "mfaLastAuthTime",

  // The HOBA client public keys registered at /.well-known/hoba/register, one
  // value per key as `<kid> <base64 DER>`. Another invention for the same
  // reason as the two above: RFC 7486 postdates the LDAP schema documents and
  // registered no attribute type, and the nearest standard thing —
  // `userPKCS12`, or `userCertificate` again — is a different object entirely.
  // It is a CREDENTIAL, which the two lists above are not: anyone who can read
  // this directory can see which key authenticates somebody, though not sign
  // with it. That is the same honest position the Kerberos passwords and
  // `oauthClientSecret` are in, and it is on GET /scim rather than left to be
  // found.
  "hobaPublicKey",

  // WHERE THIS PERSON CAME FROM, on an entry a FEDERATED sign-in created. Five
  // names, and they exist because this is the one path in this service where an
  // entry is created out of somebody ELSE'S assertion — every other entry under
  // ou=users was made because a credential was presented HERE, and the
  // difference matters to whoever reads the directory afterwards. A person with
  // `federationIssuer` on their entry has never authenticated to this service
  // at all.
  //
  // `federationAttribute` is the useful one and the one with no analogue
  // anywhere else here: it lists which of this entry's OTHER attributes came
  // off a foreign assertion rather than out of the invented-persona sweep. Both
  // kinds are ordinary directory attributes and look identical, and
  // applyVcAttributes() fills in `mail`, `givenName` and the rest for everybody
  // — so without this there is no way to tell a real email address a partner
  // sent from one this service made up, which is exactly the question a
  // federated directory entry raises. Nothing reads it; it is there to be read.
  //
  // `federationLink` (#109, 2026-09-22) is the one that DECIDES anything: a
  // partner's subject paired with the relationship it came through,
  // `<relationship> <issuer> <subject>` — see `federation/federation_links.ts`.
  // It replaced `federationSubject`, which recorded subjects without saying
  // which partner asserted each and so could not be a link.
  "federationRelationship", "federationIssuer", "federationLink",
  "federationLastSeen", "federationAttribute",
  // WHO CREATED THE ENTRY when it was not one of this service's own doors
  // (2026-10-20): `federation:<relationship>`, written once by the federated
  // sign-in that created it and by nothing else. See PROVISIONED_BY.
  "stsProvisionedBy",

  // WHAT THIS PERSON AGREED AN APPLICATION MAY ASK FOR ON THEIR BEHALF, one
  // value per (application, scope) — `20260901143000Z openid webapp1`. Invented
  // for the same reason as everything above it: OAuth 2.0 postdates the LDAP
  // schema documents and registered no attribute type for consent, and the
  // nearest standard thing is nothing at all. The grammar is
  // `common/consent.ts`'s and is argued there, including why the client_id is
  // LAST (it is the one field with no rule about what it may contain, so it
  // takes the remainder of the value).
  //
  // It is NOT a credential and it grants nothing: it is a record of an answer,
  // and the authorization endpoint reads it only to decide whether to draw the
  // consent screen. The OTHER half of the feature is `oauthGlobalConsent`,
  // which is on an APPLICATION's entry and is in the applications schema rather
  // than in this list.
  "oauthConsent",
  // WHEN THIS PERSON WITHDREW ONE (#172), `<when> <scope> <client_id>` with
  // the instant to the millisecond, one value per (application, scope). It
  // is what stops a RE-CONSENT reviving a refresh token issued before the
  // withdrawal; `common/consent.ts` argues it.
  "oauthConsentWithdrawn",
  // A CONSENT AN APPLICATION'S GLOBAL CONSENT ANSWERED FOR THIS PERSON (#537),
  // `<when> <scope> <client_id>`: written the first time a sign-in passes
  // consent because `oauthGlobalConsent` covered the scope, so
  // `/portal/consents` can show it. A record of what happened; it grants
  // nothing and the authorization endpoint never reads it.
  "oauthConsentApplied",

  // ---------------------------------------------------------------------
  // THE CREDENTIALS ON A PERSON'S OWN ENTRY THAT ARE NOT `userPassword`.
  //
  // `common/credentials.ts` writes all four. The first three have been
  // written since 2026-09-06 and were NOT in this table until 2026-09-10,
  // which is the ordinary way this table goes wrong: nothing fails, the name
  // simply renders lower-cased on `/admin/ldap/directory` — the one page
  // whose whole job is to show an entry faithfully — and the attribute looks
  // like something a foreign client added rather than something this service
  // wrote.
  //
  // There is no standard type for any of them and none is invented lightly:
  // WebAuthn, RFC 6238 and the notion of an activation link all postdate the
  // LDAP schema documents, and `userPassword` (RFC 4519 section 2.41) is the
  // only credential attribute those documents define.
  //
  // **TWO OF THE FOUR HOLD A VERIFIER AND TWO HOLD SOMETHING ELSE**, which is
  // the distinction to keep in mind when reading an entry: `userPassword` and
  // `stsActivationToken` are scrypt hashes and are useless to whoever reads
  // them; a WebAuthn public key is published by design; and
  // `stsTotpCredential` carries a SHARED SECRET, which is the one credential
  // in this directory that can be read back and used — sealed under the
  // key-encryption key in product mode for exactly that reason, and in the
  // clear in development where the key would not survive a restart.
  // `common/credentials.ts` argues all of it.
  "stsWebauthnCredential", "stsActivationToken", "stsActivationExpires",
  "stsTotpCredential",
  // THE ANDROID MARKER (#615): the credential ids of the keys above whose
  // trusted `android-key` attestation the recheck asks Google's status list
  // about, derived on every write of the keys (`deriveAndroidMarker()`) so
  // that the recheck reads its holders rather than everybody.
  "stsAndroidAttestedCredential",
  // THE WEBAUTHN USER HANDLE (#474): 64 random bytes, base64url, one per
  // person, that every passkey they register is created under and that a
  // discoverable credential hands back to say whose it is. Not a secret —
  // an authenticator stores it in the clear — and not the username, which
  // it was until #474. `common/credentials.ts` argues it.
  "stsWebauthnUserHandle",
  // AND A SECOND ONE FOR THE POST-QUANTUM LANE (#643): the handle every
  // ML-DSA passkey of the post-quantum lane is created under, so it does not
  // replace the classical one on an authenticator that holds both. Minted
  // only beside the first (`writeWebauthnUserHandle()` refuses otherwise).
  "stsWebauthnPqcUserHandle",

  // THE BOOTSTRAP ADMINISTRATOR'S FLAGS (2026-09-13) — see readPersonFlags().
  // `pwdReset` is draft-behera-ldap-password-policy's name, spelt as that draft
  // spells it, beside the `pwd*` names the password policy already uses.
  "pwdReset", "stsBootstrapAdministrator", "stsConsoleClaimedAt",
  // A DISABLED ACCOUNT (2026-09-17) — the same draft's `pwdAccountLockedTime`,
  // `000001010000Z` when an administrator disabled it. See
  // `common/credentials.ts`, `accountDisabled()`.
  "pwdAccountLockedTime",
  // WHAT AN ADMINISTRATOR PUT ON A PERSON FROM THEIR /admin/users PAGE
  // (2026-09-13) — see readPersonFlags(): a second factor required of them, and
  // the hash of a password reset link.
  "stsMfaRequired", "stsPasswordResetToken", "stsPasswordResetExpires",
  // WHO MAY ACT FOR A PERSON (#108, 2026-09-23): "sensitive and cannot be
  // delegated" (Kerberos's NOT_DELEGATED, on the person), and the one party
  // they have named as their delegate, whose `sub` becomes the `may_act` claim
  // of their access tokens. See `common/delegation_policy.ts`.
  "stsNotDelegated", "stsMayAct",
  // AND AS WHAT (#186): the semantics others may use as this person — and
  // they may use as an actor — and the default when a request says none.
  // See `common/delegation_policy.ts`.
  "stsDelegationSemantics", "stsDefaultDelegationSemantics",
  // THE MAIL CHANNEL'S ADDRESS VERIFICATION (#63, 2026-09-22) — see
  // readPersonFlags(): the address a person proved they receive mail at, and
  // the pending link's hash, expiry and the address it was sent to.
  "stsMailVerified", "stsMailVerifyToken", "stsMailVerifyExpires",
  "stsMailVerifyAddress",
  // A LOGIN NAME BESIDE THE UID (#644). The live values are what
  // usernameKeysOf indexes. The pending triple is one address waiting for
  // /portal/verify-pseudonym, and it is not a name until that link is spent.
  "stsPseudonym", "stsPseudonymVerifyToken", "stsPseudonymVerifyExpires",
  "stsPseudonymVerifyAddress",

  // THE CLIENT TRUSTSTORE'S DURABLE HALF (2026-09-12): one entry per anchor
  // under ou=trustAnchors in the DEFAULT realm. A CA certificate is public, so
  // nothing here is sealed; what makes the container sensitive is that an
  // entry decides whose client certificate becomes an identity. See
  // `trustAnchorsDn()`.
  "stsTrustAnchor", "stsTrustAnchorCertificate", "stsTrustAnchorFingerprint",
  "stsTrustAnchorAddedBy",
  // The signer truststore's two more (#1360); the three above are reused.
  "stsSignerTrustAnchor", "stsSignerTrustAnchorKind",
  "stsSignerTrustAnchorPurpose",

  // AND A FIFTH SINCE 2026-09-10: the RECOVERY CODES. It belongs with the four
  // above and it is the SECOND of them that can be read back and used — a set
  // of single-use strings, issued automatically the first time somebody
  // enrols a second factor, sealed under the key-encryption key wherever that
  // key outlives the process and stored as the strings they were shown as
  // where it does not.
  //
  // **IT IS ENCRYPTED RATHER THAN HASHED FOR A REASON THAT IS NOT ABOUT
  // CRYPTOGRAPHY**: a person may look at their remaining codes again on
  // `/portal/mfa`, and a hash cannot be shown. `common/backup_codes.ts`
  // argues it, `common/credentials.ts` does the sealing, and this module —
  // which holds no key — only ever sees whatever of the two it was handed.
  "stsBackupCodes",

  // AND A SIXTH SINCE 2026-09-11: the RFC 7523 SIGNING KEY PAIRS a person may
  // hold — SEVERAL since #1290 (2026-11-03), one value per key pair in two
  // multi-valued attributes, and a declaration. They are the PERSON's
  // counterpart to `oauthAssertion*` on an application — no code path crosses
  // the two sets, which is the same rule `applications.js` states about its
  // own pair. `common/person_assertions.js` is the register and argues the
  // whole thing, including the one refusal it exists for: a person's key
  // signs an assertion ABOUT THAT PERSON and about nobody else.
  //
  // **`stsAssertionPrivateKey` IS THE THIRD ATTRIBUTE IN THIS DIRECTORY THAT
  // CAN BE READ BACK AND USED**, after the authenticator's shared secret and
  // the recovery codes, and each of its values is sealed under the
  // key-encryption key wherever that key outlives the process for exactly
  // their reason. `stsAssertionKeyPair` is public by construction: a
  // certificate, a chain, a JWK, a kid and an expiry are all things a relying
  // party is MEANT to be given. The seven single-valued attributes it
  // replaced (`stsAssertionJwks`, `…Certificate`, `…CertificateChain`,
  // `…Kid`, `…ExpiresAt`, `…KeySource`) are gone, with no reader left.
  "stsAssertionIssuer", "stsAssertionKeyPair", "stsAssertionPrivateKey",

  // AND THE PERSON'S RFC 7522 KEY PAIRS, SINCE 2026-09-13 — a second set,
  // sharing no name with the one above it for the reason the application's
  // two share none. `stsSamlAssertionPrivateKey` is sealed like its JWT twin;
  // each record's thumbprint is the handle an XML Signature's certificate is
  // matched by, and its `source` records whether the pair was issued here or
  // a certificate was uploaded in its place.
  "stsSamlAssertionIssuer", "stsSamlAssertionKeyPair",
  "stsSamlAssertionPrivateKey",

  // AND A SEVENTH SINCE 2026-09-12: A PERSON'S KERBEROS LONG-TERM KEYS, derived
  // from their own password by `kerberos/krb5_person_keys.ts` so that a
  // product-mode KDC can authenticate them. `stsKrb5Keys` is ONE sealed value
  // carrying every enctype's key beside the name and a stamp of the password
  // hash they were derived beside; `stsKrb5KeyInfo` is the public half — kvno,
  // enctypes, when. **The first is password-equivalent and is WITHHELD** from
  // the directory dump and from an LDAP search, ciphertext included, which is
  // one step further than the three credentials above it go: nothing ever reads
  // a Kerberos key back out, so there is no reader whose view it would spoil.
  "stsKrb5Keys", "stsKrb5KeyInfo",

  // AND AN EIGHTH SINCE 2026-09-13: what ACME, EST and SCEP issued to a person,
  // the two protocol credentials, and the host names an administrator
  // registered — `common/cert_enrollment.ts` is the register. The private key,
  // the EAB key and the challenge are WITHHELD from every dump and search in
  // every mode (`cert_enrollment.withheldValues()`); the certificates and the
  // host names are public.
  "stsEnrolledCertificate", "stsEnrolledPrivateKey", "stsAcmeEabKey",
  "stsScepChallenge", "stsCertificateHostName",

  // AND A NINTH SINCE 2026-09-22 (#101): a person's APP PASSWORDS — one JSON
  // value holding each one's name, scope, scrypt hash and last use. A
  // verifier like `userPassword`, and withheld from every read like it
  // (SECRET_ATTRIBUTES). `common/credentials.ts` keeps them.
  "stsAppPassword",

  // AND A TENTH (#127, 2026-09-23): the person's IDENTITY VERIFICATIONS for
  // OpenID Connect for Identity Assurance — one JSON value holding each
  // verification's trust framework, time and evidence. Evidence carries
  // document numbers and a voucher's name, so it is withheld from every read
  // like the credentials beside it (SECRET_ATTRIBUTES).
  // `common/identity_assurance.ts` keeps them.
  "stsIdaVerification",

  // AND AN ELEVENTH (#129, 2026-09-23): the SELF-ISSUED SUBJECTS a person has
  // enrolled for SIOPv2 — a DID or an RFC 9278 JWK thumbprint URI each, one
  // JSON value per subject with its label and who enrolled it. Whoever holds
  // the key signs in as this person, so it is a credential's identifier and
  // withheld from every read (SECRET_ATTRIBUTES). `oid4vc/siop.ts` keeps them.
  "stsSelfIssuedSubject",

  // AND ITS PUBLISHED DIDs (#1291, 2026-11-03): each did:web this realm
  // created and publishes for the person, one JSON value per DID — its
  // random id, the DID, the custody, every version of its keys and what
  // authorized each, its deactivation, and in `realm` custody the private
  // key, sealed. The history is what a verifier resolves a versioned DID
  // URL against, and the key is a credential, so the whole value is
  // withheld from every read (SECRET_ATTRIBUTES). `oid4vc/person_did.ts`
  // keeps them; the random id finds its entry through a per-realm index
  // (`did.personDids`), never a walk.
  "stsPublishedDid",

  // AND THEIR PROFILE PHOTO'S RECORD (#719): one JSON value saying which row
  // of `profilePhoto.images` is theirs, whose it was, and whether they
  // declined a partner's copy. The image is not on the entry, because every
  // token reads the entry; `common/profile_photo.ts` argues it. Withheld
  // (SECRET_ATTRIBUTES): the id is the capability the address is made of, and
  // the partner's address is nobody's business.
  "stsProfilePhoto",

  // AND THE DEVICE REGISTER'S (#130, 2026-09-23): RFC 4519's `device` class
  // has `cn`, `owner` and `description` and nothing about what a device is
  // used for or what it holds, so these are this service's own — the class
  // that carries them, the applications that used the device (DNs), the
  // SHA-256 of its Native SSO device_secret (withheld, SECRET_ATTRIBUTES),
  // the sign-on session the secret is good for, and when it was last used.
  // `common/devices.ts` keeps them.
  "stsDevice", "stsDeviceApplication", "stsDeviceSecretHash",
  "stsDeviceSession", "stsDeviceLastUsed",
  // AND THE REST OF WHAT A DEVICE IS (#164, 2026-09-26): its owner's kind (a
  // person or an application), its keys (one JSON value each, public
  // material only) and their thumbprint index, its attestation level,
  // compliance and status with the last change of each, three descriptive
  // labels and how it was enrolled. `common/devices.ts` argues the layout.
  "stsDeviceOwnerKind", "stsDeviceKey", "stsDeviceKeyThumbprint",
  "stsDeviceAttestation", "stsDeviceCompliance", "stsDeviceComplianceChange",
  "stsDeviceStatus", "stsDeviceStatusChange", "stsDevicePlatform",
  "stsDeviceModel", "stsDeviceOs", "stsDeviceEnrolment",
  // AND EACH LINKED WEBAUTHN CREDENTIAL'S ID (#164 phase 6), derived from
  // stsDeviceKey like the thumbprints, so a sign-in finds its device by
  // index.
  "stsDeviceCredentialId",
  // AND EACH ANDROID-ATTESTED KEY'S ID (#615), derived from stsDeviceKey
  // like the two above, so the Android attestation recheck reads the
  // devices holding one rather than every device.
  "stsDeviceAndroidKey",
  // AND ITS RISK LEVEL (#164 phase 4): LOW, MEDIUM or HIGH, and the last
  // change of it — what CAEP's risk-level-change with principal DEVICE
  // reports, set by phase 5's risk scoring and by a compromise.
  "stsDeviceRiskLevel", "stsDeviceRiskChange",
  // AND A REMEMBERED BROWSER'S STATE (#265): its token generation and the
  // browser it was bound to, as one JSON value — `common/browser_devices.ts`.
  "stsDeviceBrowser",

  // AND A PERSON'S CIBA USER CODE (#131, 2026-09-23): a secret they set on
  // /portal/ciba that a backchannel authentication request must carry when
  // its client registered backchannel_user_code_parameter. Hashed like a
  // password, and withheld like one (SECRET_ATTRIBUTES).
  "stsCibaUserCode",

  // AND THE OPENID FEDERATION REGISTER'S (#132, 2026-09-23): the class of an
  // `ou=oidfed` entry, its kind (`keys`, `subordinate`, `anchor`,
  // `mark-type`, `issued-mark`, `held-mark`), the Entity Identifier it is
  // about, its record as one JSON value, and — on the realm's one `keys`
  // entry — the Federation Entity Key table, whose rows carry the private
  // keys, sealed where keys persist (withheld, SECRET_ATTRIBUTES).
  // `oidfed/oidfed_store.ts` and `oidfed/federation_keys.ts` keep them.
  "stsOidfedEntry", "stsOidfedKind", "stsOidfedEntityId", "stsOidfedData",
  "stsOidfedKeys",

  // AND A PERSON'S ACCOUNT ID AT EACH CLIENT (#148, Enterprise Extensions
  // section 2.3): `<client_id> <aud_sub>` per value, recorded by an
  // administrator and sent as the ID Token's `aud_sub` to that client.
  "stsAudSub",

  // AND THE CLAIMS PROVIDER REGISTER'S (#147, 2026-09-24): the class of an
  // `ou=claimproviders` entry, its record as one JSON value, and its client
  // secret at that provider (sealed where keys persist, and withheld,
  // SECRET_ATTRIBUTES); and on a PERSON, the tokens each provider they
  // linked issued them, one JSON value, sealed and withheld the same way.
  // `oauth-oidc/claims_providers.ts` keeps them.
  "stsClaimProvider", "stsClaimProviderData", "stsClaimProviderSecret",
  "stsClaimSourceTokens",

  // AN ATTRIBUTE SOURCE (#94): the register entry's class and its one JSON
  // value; and on a PERSON, which attributes each source wrote
  // (`<source>:<attribute>`) and when each last read them (`<source>=<time>`).
  "stsAttributeSource", "stsAttributeSourceData", "stsAttributeSourced",
  "stsAttributeSourceSeen",

  // AND A SUBORDINATE'S EVENT HISTORY (#137, 2026-09-24): one JSON event per
  // value of an `events` entry, appended and never rewritten, merged by
  // value when two nodes append at once (persistence/directory_merge.js).
  // `oidfed/subordinate_events.ts` writes them.
  "stsOidfedEvent",

  // AND THE KERBEROS TRUST REGISTER'S (#430, 2026-10-19): the class of an
  // `ou=kerberosTrusts` entry, its record as one JSON value, and its keys
  // (sealed where keys persist, and withheld, SECRET_ATTRIBUTES) — beside
  // the six names of Active Directory's trustedDomain object ([MS-ADTS]
  // 6.1.6.7) it mirrors for an `ldapsearch`. `kerberos/krb5_trusts.ts`
  // writes them.
  "stsKrb5Trust", "stsKrb5TrustData", "stsKrb5TrustKeys",
  "trustPartner", "flatName", "securityIdentifier", "trustDirection",
  "trustAttributes", "trustType"
],
  secret: #[
  "userpassword", "pwdhistory",
  // A service account's previous password (#221): a verifier like
  // userPassword during the rotation's overlap.
  "stspreviouspassword",
  "oauthclientsecret", "appregistrationaccesstoken", "fedclientsecret",
  "oauthassertionprivatekey", "oauthsamlassertionprivatekey",
  // An application DID's private keys (2026-10-01), sealed like the two
  // above and withheld from every directory read like them.
  "didprivatekeys",
  // A secret destination's write credential (#221 P3), sealed like the
  // three above and withheld from every directory read.
  "secretdestcredential",
  // An outbound SCIM client's three credentials (#552), sealed like the
  // destination's and withheld from every directory read.
  "scimclientpassword", "scimclientoauthclientsecret",
  "scimclienttlsprivatekey",
  "stsassertionprivatekey", "stssamlassertionprivatekey",
  "ststotpcredential", "stsbackupcodes", "stsactivationtoken",
  // A person's app passwords (#101): scrypt hashes, a verifier like
  // userPassword and withheld like it.
  "stsapppassword",
  // A person's identity verifications (#127): evidence with document
  // numbers, personal data no directory read should hand out.
  "stsidaverification",
  // A person's enrolled self-issued subjects (#129): whoever holds one of
  // these keys signs in as them.
  "stsselfissuedsubject",
  // A person's published DIDs (#1291): the version history a verifier
  // resolves, and in `realm` custody the sealed private key.
  "stspublisheddid",
  // A person's profile photo record (#719): the id its public address is
  // made of, and the partner address it was copied from.
  "stsprofilephoto",
  // A device's Native SSO secret, hashed (#130): a credential's verifier.
  "stsdevicesecrethash",
  // A person's CIBA user code, hashed (#131).
  "stscibausercode",
  // A Claims Provider's client secret, and a person's tokens at the Claims
  // Providers they linked (#147): credentials, sealed where keys persist.
  "stsclaimprovidersecret", "stsclaimsourcetokens",
  // A password reset link's hash (2026-09-13), for the activation token's
  // reason beside it.
  "stspasswordresettoken",
  // An address verification link's hash (#63), for the same reason.
  "stsmailverifytoken",
  // A pseudonym verification link's hash (#644), the same reason: the
  // token itself never leaves the directory.
  "stspseudonymverifytoken",
  "stskrb5keys", "krb5servicekeys",
  // Certificate enrollment (2026-09-13): a private key this service generated
  // for an enrolled certificate, an ACME EAB key and a SCEP challenge record.
  "stsenrolledprivatekey", "appenrolledprivatekey",
  "stsacmeeabkey", "appacmeeabkey", "stsscepchallenge", "appscepchallenge",
  // GNAP (2026-09-12): a client's shared secret for a key reference, and a
  // resource server's macaroon root key. Either one mints a working credential.
  "gnapsymmetrickey", "gnapmacaroonkey",
  // A federation relationship's key table (#168): every row carries the
  // private key the partner's assertions are decrypted with.
  "fedencryptionkey",
  // The realm's Federation Entity Key table (#132): every row carries the
  // private key the realm's federation statements are signed with.
  "stsoidfedkeys",
  // A Kerberos trust's keys (#430): the shared password or the generated
  // inter-realm keys, either of which is every ticket the partner accepts.
  "stskrb5trustkeys"
]
})
model DirectoryNames {}
