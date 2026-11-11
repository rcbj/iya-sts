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
  uid?: (string)[];
  @attr(#{what: "Named on the People section."})
  cn?: (string)[];
  @attr(#{what: "Named on the People section."})
  sn?: (string)[];
  @attr(#{what: "Named on the People section."})
  givenName?: (string)[];
  @attr(#{what: "Named on the People section."})
  displayName?: string;
  @attr(#{what: "Named on the People section."})
  mail?: (string)[];
  @attr(#{what: "Named on the People section."})
  userCertificate?: (string)[];
  @attr(#{what: "Named on the People section."})
  title?: (string)[];
  @attr(#{what: "Named on the People section."})
  employeeType?: (string)[];
  @attr(#{what: "Named on the People section."})
  telephoneNumber?: (string)[];
  @attr(#{what: "Named on the People section."})
  mobile?: (string)[];
  @attr(#{what: "Named on the People section."})
  street?: (string)[];
  @attr(#{what: "Named on the People section."})
  l?: (string)[];
  @attr(#{what: "Named on the People section."})
  st?: (string)[];
  @attr(#{what: "Named on the People section."})
  postalCode?: (string)[];
  @attr(#{what: "Named on the People section."})
  c?: string;
  @attr(#{what: "Named on the People section."})
  postalAddress?: (string)[];
  @attr(#{what: "Named on the People section."})
  o?: (string)[];
  @attr(#{what: "Named on the People section."})
  ou?: (string)[];
  @attr(#{what: "Named on the People section."})
  departmentNumber?: (string)[];
  @attr(#{what: "Named on the People section."})
  employeeNumber?: string;
  @attr(#{what: "Named on the People section."})
  preferredLanguage?: string;
  @attr(#{what: "Named on the People section."})
  labeledURI?: (string)[];
  @attr(#{what: "Named on the People section."})
  @link(#{to: "person", cardinality: "single", owns: false, what: "RFC 2798 manager, a DN."})
  manager?: (string)[];
  @attr(#{what: "Named on the People section."})
  schacDateOfBirth?: string;
  @attr(#{what: "Named on the People section."})
  schacCountryOfCitizenship?: (string)[];
  @attr(#{what: "Named on the People section."})
  schacPersonalTitle?: (string)[];
  @attr(#{what: "Named on the People section."})
  salutation?: (string)[];
  @attr(#{what: "Named on the People section."})
  birthFamilyName?: (string)[];
  @attr(#{what: "Named on the People section."})
  birthGivenName?: (string)[];
  @attr(#{what: "Named on the People section."})
  birthMiddleName?: (string)[];
  @attr(#{what: "Named on the People section."})
  alsoKnownAs?: (string)[];
  @attr(#{what: "Named on the People section."})
  placeOfBirthCountry?: string;
  @attr(#{what: "Named on the People section."})
  placeOfBirthRegion?: string;
  @attr(#{what: "Named on the People section."})
  placeOfBirthLocality?: string;
  @attr(#{what: "Named on the People section."})
  schacGender?: string;
  @attr(#{what: "Named on the People section."})
  middleName?: string;
  @attr(#{what: "Named on the People section."})
  timeZone?: string;
  @attr(#{what: "Named on the People section."})
  pictureUrl?: string;
  @attr(#{what: "Named on the People section."})
  profileUrl?: string;
  @attr(#{what: "Named on the People section."})
  scimExternalId?: string;
  @attr(#{what: "Named on the People section."})
  userPrincipalName?: string;
  @attr(#{what: "Named on the People section."})
  stsWebauthnCredential?: (DirectoryJson)[];
  @attr(#{what: "Named on the People section."})
  stsKrb5KeyInfo?: DirectoryJson;
  @attr(#{what: "Named on the People section."})
  hobaPublicKey?: (string)[];
  @attr(#{what: "Named on the People section."})
  stsActivationExpires?: DirectoryTime;
  @attr(#{what: "Named on the People section."})
  stsPasswordResetExpires?: DirectoryTime;
  @attr(#{what: "Named on the People section."})
  pwdChangedTime?: string;
  @attr(#{what: "Named on the People section."})
  pwdHistory?: (string)[];
  @attr(#{what: "Named on the People section."})
  pwdReset?: string;
  @attr(#{what: "Named on the People section."})
  pwdAccountLockedTime?: string;
  @attr(#{what: "Named on the People section."})
  stsBackupCodes?: DirectoryJson;
  @attr(#{what: "Named on the People section."})
  stsActivationToken?: string;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  userPassword?: (string)[];
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsProfilePhoto?: DirectoryJson;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsTotpCredential?: DirectoryJson;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsAppPassword?: DirectoryJson;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsPasswordResetToken?: string;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsKrb5Keys?: string;
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsSelfIssuedSubject?: (DirectoryJson)[];
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsPublishedDid?: (DirectoryJson)[];
  @attr(#{what: "Named on the People section as withheld or sealed.", sensitive: true})
  stsCibaUserCode?: string;
  @attr(#{})
  x509subject?: (DirectoryDn)[];
  @attr(#{})
  x509issuer?: (DirectoryDn)[];
  @attr(#{})
  x509serialNumber?: (string)[];
  @attr(#{})
  x509notBefore?: (string)[];
  @attr(#{})
  x509notAfter?: (string)[];
  @attr(#{})
  x509fingerprint256?: (string)[];
  @attr(#{})
  x509svidsIssued?: DirectoryInteger;
  @attr(#{})
  x509firstIssued?: DirectoryTime;
  @attr(#{})
  x509lastIssued?: DirectoryTime;
  @attr(#{})
  didSubject?: (string)[];
  @attr(#{})
  didMethod?: (string)[];
  @attr(#{})
  spiffeSubject?: (string)[];
  @attr(#{})
  spiffePath?: string;
  @attr(#{})
  spiffeTrustDomain?: string;
  @attr(#{})
  spiffeCredentialStatus?: string;
  @attr(#{})
  spiffeCredentialStatusReason?: string;
  @attr(#{})
  spiffeRevokedAt?: DirectoryTime;
  @attr(#{})
  authnMethod?: (string)[];
  @attr(#{})
  mfaAuthenticated?: DirectoryBoolean;
  @attr(#{})
  mfaLastAuthTime?: DirectoryTime;
  @attr(#{})
  federationIssuer?: (string)[];
  @attr(#{})
  federationLink?: (string)[];
  @attr(#{})
  federationLastSeen?: DirectoryTime;
  @attr(#{})
  federationAttribute?: (string)[];
  @attr(#{})
  stsProvisionedBy?: string;
  @attr(#{})
  oauthConsent?: (string)[];
  @attr(#{})
  oauthConsentWithdrawn?: (string)[];
  @attr(#{})
  oauthConsentApplied?: (string)[];
  @attr(#{})
  stsAndroidAttestedCredential?: (string)[];
  @attr(#{})
  stsWebauthnUserHandle?: DirectoryBase64;
  @attr(#{})
  stsWebauthnPqcUserHandle?: DirectoryBase64;
  @attr(#{})
  stsBootstrapAdministrator?: DirectoryBoolean;
  @attr(#{})
  stsConsoleClaimedAt?: DirectoryTime;
  @attr(#{})
  stsMfaRequired?: DirectoryBoolean;
  @attr(#{})
  stsNotDelegated?: DirectoryBoolean;
  @attr(#{})
  stsMayAct?: string;
  @attr(#{})
  stsDelegationSemantics?: (string)[];
  @attr(#{})
  stsDefaultDelegationSemantics?: string;
  @attr(#{})
  stsMailVerified?: string;
  @attr(#{})
  stsMailVerifyToken?: string;
  @attr(#{})
  stsMailVerifyExpires?: DirectoryTime;
  @attr(#{})
  stsMailVerifyAddress?: string;
  @attr(#{})
  stsPseudonym?: (string)[];
  @attr(#{})
  stsPseudonymVerifyToken?: string;
  @attr(#{})
  stsPseudonymVerifyExpires?: DirectoryTime;
  @attr(#{})
  stsPseudonymVerifyAddress?: string;
  @attr(#{})
  stsAuthzenApplication?: (string)[];
  @attr(#{})
  stsAuthzenCallbackUri?: (string)[];
  @attr(#{})
  stsAssertionIssuer?: (string)[];
  @attr(#{})
  stsAssertionKeyPair?: (DirectoryJson)[];
  @attr(#{})
  stsAssertionPrivateKey?: (string)[];
  @attr(#{})
  stsSamlAssertionIssuer?: (string)[];
  @attr(#{})
  stsSamlAssertionKeyPair?: (DirectoryJson)[];
  @attr(#{})
  stsSamlAssertionPrivateKey?: (string)[];
  @attr(#{})
  stsEnrolledCertificate?: (DirectoryJson)[];
  @attr(#{})
  stsEnrolledPrivateKey?: (string)[];
  @attr(#{})
  stsAcmeEabKey?: (DirectoryJson)[];
  @attr(#{})
  stsScepChallenge?: (DirectoryJson)[];
  @attr(#{})
  stsCertificateHostName?: (string)[];
  @attr(#{})
  stsIdaVerification?: DirectoryJson;
  @attr(#{})
  stsAudSub?: (string)[];
  @attr(#{})
  stsClaimSourceTokens?: DirectoryJson;
}
