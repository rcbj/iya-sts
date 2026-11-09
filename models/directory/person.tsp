// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/person.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// `sensitive` is set where the page says the value is withheld or sealed. Hashed is
// not the same claim. A row with no sentence takes the comment above its name in
// names.tsp. Whether a value is withheld from every reader of the directory is
// that file's `secret` list.

@entry(#{
  id: "person",
  source: "catalogue",
  container: "ou=users",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md People",
  note: "No SCHEMA export. One person is one entry, RDN uid.",
  objectClasses: #[
    #{
      name: "top",
      standard: true,
      what: "The abstract class every entry carries."
    },
    #{
      name: "person",
      standard: true,
      what: "RFC 4519 person."
    },
    #{
      name: "organizationalPerson",
      standard: true,
      what: "RFC 4519 organizationalPerson."
    },
    #{
      name: "inetOrgPerson",
      standard: true,
      what: "RFC 2798 inetOrgPerson."
    }
  ]
})
model Person {
  @attr(#{what: "Named on the People section."})
  uid?: unknown;
  @attr(#{what: "Named on the People section."})
  cn?: unknown;
  @attr(#{what: "Named on the People section."})
  sn?: unknown;
  @attr(#{what: "Named on the People section."})
  givenName?: unknown;
  @attr(#{what: "Named on the People section."})
  displayName?: unknown;
  @attr(#{what: "Named on the People section."})
  mail?: unknown;
  @attr(#{what: "Named on the People section."})
  userCertificate?: unknown;
  @attr(#{what: "Named on the People section."})
  title?: unknown;
  @attr(#{what: "Named on the People section."})
  employeeType?: unknown;
  @attr(#{what: "Named on the People section."})
  telephoneNumber?: unknown;
  @attr(#{what: "Named on the People section."})
  mobile?: unknown;
  @attr(#{what: "Named on the People section."})
  street?: unknown;
  @attr(#{what: "Named on the People section."})
  l?: unknown;
  @attr(#{what: "Named on the People section."})
  st?: unknown;
  @attr(#{what: "Named on the People section."})
  postalCode?: unknown;
  @attr(#{what: "Named on the People section."})
  c?: unknown;
  @attr(#{what: "Named on the People section."})
  postalAddress?: unknown;
  @attr(#{what: "Named on the People section."})
  o?: unknown;
  @attr(#{what: "Named on the People section."})
  ou?: unknown;
  @attr(#{what: "Named on the People section."})
  departmentNumber?: unknown;
  @attr(#{what: "Named on the People section."})
  employeeNumber?: unknown;
  @attr(#{what: "Named on the People section."})
  preferredLanguage?: unknown;
  @attr(#{what: "Named on the People section."})
  labeledURI?: unknown;
  @attr(#{what: "Named on the People section."})
  @link(#{to: "person", cardinality: "single", owns: false, what: "RFC 2798 manager, a DN."})
  manager?: unknown;
  @attr(#{what: "Named on the People section."})
  schacDateOfBirth?: unknown;
  @attr(#{what: "Named on the People section."})
  schacCountryOfCitizenship?: unknown;
  @attr(#{what: "Named on the People section."})
  schacPersonalTitle?: unknown;
  @attr(#{what: "Named on the People section."})
  salutation?: unknown;
  @attr(#{what: "Named on the People section."})
  birthFamilyName?: unknown;
  @attr(#{what: "Named on the People section."})
  birthGivenName?: unknown;
  @attr(#{what: "Named on the People section."})
  birthMiddleName?: unknown;
  @attr(#{what: "Named on the People section."})
  alsoKnownAs?: unknown;
  @attr(#{what: "Named on the People section."})
  placeOfBirthCountry?: unknown;
  @attr(#{what: "Named on the People section."})
  placeOfBirthRegion?: unknown;
  @attr(#{what: "Named on the People section."})
  placeOfBirthLocality?: unknown;
  @attr(#{what: "Named on the People section."})
  schacGender?: unknown;
  @attr(#{what: "Named on the People section."})
  middleName?: unknown;
  @attr(#{what: "Named on the People section."})
  timeZone?: unknown;
  @attr(#{what: "Named on the People section."})
  pictureUrl?: unknown;
  @attr(#{what: "Named on the People section."})
  profileUrl?: unknown;
  @attr(#{what: "Named on the People section."})
  scimExternalId?: unknown;
  @attr(#{what: "Named on the People section."})
  userPrincipalName?: unknown;
  @attr(#{what: "Named on the People section."})
  stsWebauthnCredential?: unknown;
  @attr(#{what: "Named on the People section."})
  stsKrb5KeyInfo?: unknown;
  @attr(#{what: "Named on the People section."})
  hobaPublicKey?: unknown;
  @attr(#{what: "Named on the People section."})
  stsActivationExpires?: unknown;
  @attr(#{what: "Named on the People section."})
  stsPasswordResetExpires?: unknown;
  @attr(#{what: "Named on the People section."})
  pwdChangedTime?: unknown;
  @attr(#{what: "Named on the People section."})
  pwdHistory?: unknown;
  @attr(#{what: "Named on the People section."})
  pwdReset?: unknown;
  @attr(#{what: "Named on the People section."})
  pwdAccountLockedTime?: unknown;
  @attr(#{what: "Named on the People section."})
  stsBackupCodes?: unknown;
  @attr(#{what: "Named on the People section."})
  stsActivationToken?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  userPassword?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsProfilePhoto?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsTotpCredential?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsAppPassword?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsPasswordResetToken?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsKrb5Keys?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsSelfIssuedSubject?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsPublishedDid?: unknown;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsCibaUserCode?: unknown;
  @attr(#{})
  x509subject?: unknown;
  @attr(#{})
  x509issuer?: unknown;
  @attr(#{})
  x509serialNumber?: unknown;
  @attr(#{})
  x509notBefore?: unknown;
  @attr(#{})
  x509notAfter?: unknown;
  @attr(#{})
  x509fingerprint256?: unknown;
  @attr(#{})
  x509svidsIssued?: unknown;
  @attr(#{})
  x509firstIssued?: unknown;
  @attr(#{})
  x509lastIssued?: unknown;
  @attr(#{})
  didSubject?: unknown;
  @attr(#{})
  didMethod?: unknown;
  @attr(#{})
  spiffeSubject?: unknown;
  @attr(#{})
  spiffePath?: unknown;
  @attr(#{})
  spiffeTrustDomain?: unknown;
  @attr(#{})
  spiffeCredentialStatus?: unknown;
  @attr(#{})
  spiffeCredentialStatusReason?: unknown;
  @attr(#{})
  spiffeRevokedAt?: unknown;
  @attr(#{})
  authnMethod?: unknown;
  @attr(#{})
  mfaAuthenticated?: unknown;
  @attr(#{})
  mfaLastAuthTime?: unknown;
  @attr(#{})
  federationIssuer?: unknown;
  @attr(#{})
  federationLink?: unknown;
  @attr(#{})
  federationLastSeen?: unknown;
  @attr(#{})
  federationAttribute?: unknown;
  @attr(#{})
  stsProvisionedBy?: unknown;
  @attr(#{})
  oauthConsent?: unknown;
  @attr(#{})
  oauthConsentWithdrawn?: unknown;
  @attr(#{})
  oauthConsentApplied?: unknown;
  @attr(#{})
  stsAndroidAttestedCredential?: unknown;
  @attr(#{})
  stsWebauthnUserHandle?: unknown;
  @attr(#{})
  stsWebauthnPqcUserHandle?: unknown;
  @attr(#{})
  stsBootstrapAdministrator?: unknown;
  @attr(#{})
  stsConsoleClaimedAt?: unknown;
  @attr(#{})
  stsMfaRequired?: unknown;
  @attr(#{})
  stsNotDelegated?: unknown;
  @attr(#{})
  stsMayAct?: unknown;
  @attr(#{})
  stsDelegationSemantics?: unknown;
  @attr(#{})
  stsDefaultDelegationSemantics?: unknown;
  @attr(#{})
  stsMailVerified?: unknown;
  @attr(#{})
  stsMailVerifyToken?: unknown;
  @attr(#{})
  stsMailVerifyExpires?: unknown;
  @attr(#{})
  stsMailVerifyAddress?: unknown;
  @attr(#{})
  stsPseudonym?: unknown;
  @attr(#{})
  stsPseudonymVerifyToken?: unknown;
  @attr(#{})
  stsPseudonymVerifyExpires?: unknown;
  @attr(#{})
  stsPseudonymVerifyAddress?: unknown;
  @attr(#{})
  stsAssertionIssuer?: unknown;
  @attr(#{})
  stsAssertionKeyPair?: unknown;
  @attr(#{})
  stsAssertionPrivateKey?: unknown;
  @attr(#{})
  stsSamlAssertionIssuer?: unknown;
  @attr(#{})
  stsSamlAssertionKeyPair?: unknown;
  @attr(#{})
  stsSamlAssertionPrivateKey?: unknown;
  @attr(#{})
  stsEnrolledCertificate?: unknown;
  @attr(#{})
  stsEnrolledPrivateKey?: unknown;
  @attr(#{})
  stsAcmeEabKey?: unknown;
  @attr(#{})
  stsScepChallenge?: unknown;
  @attr(#{})
  stsCertificateHostName?: unknown;
  @attr(#{})
  stsIdaVerification?: unknown;
  @attr(#{})
  stsAudSub?: unknown;
  @attr(#{})
  stsClaimSourceTokens?: unknown;
}
