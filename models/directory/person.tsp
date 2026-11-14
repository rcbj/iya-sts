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
  @attr(#{what: "The username, which names the entry (uid=<username>) and which every sign-in finds the person by, released as the preferred_username claim. Written when the entry is created; a rename is not an attribute edit."})
  uid?: (string)[];
  @attr(#{what: "The person's common name, released as the name claim. On person's MUST list, so it cannot be emptied. An administrator, the person on /portal, SCIM or a federated sign-in writes it; in development an entry this service creates gets an invented one."})
  cn?: (string)[];
  @attr(#{what: "The person's surname. On person's MUST list, so it cannot be emptied. Written as cn is, and released as the family_name claim."})
  sn?: (string)[];
  @attr(#{what: "The person's given name, released as the given_name claim. Written as cn is."})
  givenName?: (string)[];
  @attr(#{what: "The name shown for the person, released as the nickname claim. Single-valued in RFC 2798."})
  displayName?: string;
  @attr(#{what: "The person's email address, released as the email claim. Written by its own control (set-mail) rather than the attribute editor, because a change is verified and the former address is told."})
  mail?: (string)[];
  @attr(#{what: "Certificates stored on the person, as userCertificate;binary (base64 DER). A certificate from an outside certificate authority is an identity only as the one entry storing it, byte for byte. Written from the person's console page, /admin-api/users/add-certificate and remove-certificate, or an LDAP modify."})
  userCertificate?: (string)[];
  @attr(#{what: "The person's job title, released as the job_title claim and mapped by SCIM."})
  title?: (string)[];
  @attr(#{what: "The person's relationship to the organisation, such as employee or contractor, released as the employee_type claim and mapped by SCIM."})
  employeeType?: (string)[];
  @attr(#{what: "The person's telephone numbers, released as the phone_number claim and mapped by SCIM."})
  telephoneNumber?: (string)[];
  @attr(#{what: "The person's mobile numbers, released as the msisdn claim and mapped by SCIM."})
  mobile?: (string)[];
  @attr(#{what: "The street part of the person's address, released in the address claim."})
  street?: (string)[];
  @attr(#{what: "The locality (city) of the person's address, released in the address claim."})
  l?: (string)[];
  @attr(#{what: "The state or province of the person's address, released in the address claim."})
  st?: (string)[];
  @attr(#{what: "The postal code of the person's address, released in the address claim."})
  postalCode?: (string)[];
  @attr(#{what: "The country of the person's address, released in the address claim: an ISO 3166-1 alpha-2 code, stored upper-case. Single-valued in RFC 4519."})
  c?: string;
  @attr(#{what: "The person's whole postal address as one formatted value, released in the address claim."})
  postalAddress?: (string)[];
  @attr(#{what: "The organisation the person belongs to, released as the organization claim and mapped by SCIM."})
  o?: (string)[];
  @attr(#{what: "The organisational unit or division the person belongs to, released as the organizational_unit claim and mapped by SCIM."})
  ou?: (string)[];
  @attr(#{what: "The person's department, released as the department claim and mapped by SCIM."})
  departmentNumber?: (string)[];
  @attr(#{what: "The person's employee number, released as the employee_number claim and mapped by SCIM. Single-valued in RFC 2798."})
  employeeNumber?: string;
  @attr(#{what: "The person's preferred language, in RFC 2798's Accept-Language syntax, released as the locale claim. Single-valued in RFC 2798."})
  preferredLanguage?: string;
  @attr(#{what: "A web page about the person: an http or https URL, optionally followed by a label. Released as the website claim."})
  labeledURI?: (string)[];
  @attr(#{what: "The DN of the person's manager. The shape of a DN is checked; the entry it names need not exist here."})
  @link(#{to: "person", cardinality: "single", owns: false, what: "RFC 2798 manager, a DN."})
  manager?: (string)[];
  @attr(#{kind: "single", what: "The person's date of birth, stored YYYYMMDD (SCHAC's form), released as the birthdate claim. One value: the attribute editor refuses a second."})
  schacDateOfBirth?: string;
  @attr(#{kind: "multi", what: "The person's nationalities, one ISO 3166-1 alpha-2 code per value, released as the nationalities claim. SCHAC's name."})
  schacCountryOfCitizenship?: (string)[];
  @attr(#{kind: "multi", what: "The person's honorific, such as Dr, released as the Identity Assurance title claim. SCHAC's name."})
  schacPersonalTitle?: (string)[];
  @attr(#{kind: "multi", what: "A formal salutation for the person, released as the Identity Assurance salutation claim. This service's own name: no standard attribute type carries it."})
  salutation?: (string)[];
  @attr(#{kind: "multi", what: "The person's family name at birth, released as the Identity Assurance birth_family_name claim. This service's own name."})
  birthFamilyName?: (string)[];
  @attr(#{kind: "multi", what: "The person's given name at birth, released as the Identity Assurance birth_given_name claim. This service's own name."})
  birthGivenName?: (string)[];
  @attr(#{kind: "multi", what: "The person's middle name at birth, released as the Identity Assurance birth_middle_name claim. This service's own name."})
  birthMiddleName?: (string)[];
  @attr(#{kind: "multi", what: "Other names the person is known by, released as the Identity Assurance also_known_as claim. This service's own name."})
  alsoKnownAs?: (string)[];
  @attr(#{kind: "single", what: "The country the person was born in, an ISO 3166-1 alpha-2 code, released in the Identity Assurance place_of_birth claim. One value: the attribute editor refuses a second."})
  placeOfBirthCountry?: string;
  @attr(#{kind: "single", what: "The region the person was born in, released in the Identity Assurance place_of_birth claim. One value: the attribute editor refuses a second."})
  placeOfBirthRegion?: string;
  @attr(#{kind: "single", what: "The locality the person was born in, released in the Identity Assurance place_of_birth claim. One value: the attribute editor refuses a second."})
  placeOfBirthLocality?: string;
  @attr(#{kind: "single", what: "The person's gender as an ISO/IEC 5218 code, released as the gender claim (male, female, not known or not applicable). SCHAC's name, single-valued."})
  schacGender?: string;
  @attr(#{kind: "single", what: "The person's middle name, released as the middle_name claim. This service's own name; one value."})
  middleName?: string;
  @attr(#{kind: "single", what: "The person's time zone, an IANA zone name such as Europe/Stockholm, released as the zoneinfo claim. This service's own name; one value."})
  timeZone?: string;
  @attr(#{kind: "single", what: "The address of the person's picture, released as the picture claim. While the person has a profile photo this service holds, it is that photo's address. This service's own name; one value."})
  pictureUrl?: string;
  @attr(#{kind: "single", what: "The address of the person's profile page, an http or https URL, released as the profile claim. This service's own name; one value."})
  profileUrl?: string;
  @attr(#{kind: "single", what: "SCIM's externalId: the provisioning client's own identifier for the person, stored verbatim by /scim/v2 and read by nothing else."})
  scimExternalId?: string;
  @attr(#{kind: "single", what: "The person's user principal name, read by certificate enrollment's smartcard-logon profile as the certificate's UPN. Nothing in this service writes it; a client supplies it."})
  userPrincipalName?: string;
  @attr(#{kind: "multi", what: "The person's registered WebAuthn public keys, one JSON value per passkey or security key. Public by design. Written by registration on /portal and the sign-in steps."})
  stsWebauthnCredential?: (DirectoryJson)[];
  @attr(#{kind: "single", what: "The public half of the person's Kerberos keys, one JSON value: the key version number, the encryption types and when they were derived."})
  stsKrb5KeyInfo?: DirectoryJson;
  @attr(#{kind: "multi", what: "The person's RFC 7486 HOBA client public keys, one value per key as `<kid> <base64 DER>`, registered at /.well-known/hoba/register. Public."})
  hobaPublicKey?: (string)[];
  @attr(#{kind: "single", what: "When the pending activation link stops working."})
  stsActivationExpires?: DirectoryTime;
  @attr(#{kind: "single", what: "When the pending password reset link stops working."})
  stsPasswordResetExpires?: DirectoryTime;
  @attr(#{what: "When the person's password last changed (draft-behera-ldap-password-policy). Maintained by the password policy."})
  pwdChangedTime?: string;
  @attr(#{what: "Earlier password hashes, kept for the password policy's history rule (draft-behera-ldap-password-policy). Withheld from every read."})
  pwdHistory?: (string)[];
  @attr(#{what: "TRUE when the password must be changed at the next sign-in (draft-behera-ldap-password-policy)."})
  pwdReset?: string;
  @attr(#{what: "Set while the account is disabled: 000001010000Z means an administrator, or SCIM's active: false, disabled it. Every door refuses the person while any value is present (draft-behera-ldap-password-policy)."})
  pwdAccountLockedTime?: string;
  @attr(#{kind: "single", what: "The person's recovery codes, one JSON value holding each code's hash and when it was used, and the counts. Issued when a second factor is first enrolled. Withheld from every read."})
  stsBackupCodes?: DirectoryJson;
  @attr(#{kind: "single", what: "The scrypt hash of a pending activation link. Withheld from every read."})
  stsActivationToken?: string;
  @attr(#{what: "The person's password as an scrypt hash, hashed on every write including an LDAP modify. Written by the sign-in, the portal, an administrator, SCIM or an LDAP modify, each through the password policy. Withheld from every read.", sensitive: true})
  userPassword?: (string)[];
  @attr(#{kind: "single", what: "The person's profile photo record, one JSON value: which stored image is theirs, whose it was, and whether they declined a partner's copy. The image itself is not on the entry. Written only by the portal and a federated sign-in, and withheld from every read.", sensitive: true})
  stsProfilePhoto?: DirectoryJson;
  @attr(#{kind: "single", what: "The person's RFC 6238 authenticator secret, one JSON value. Sealed under the key-encryption key in product mode, and withheld from every read.", sensitive: true})
  stsTotpCredential?: DirectoryJson;
  @attr(#{kind: "single", what: "The person's app passwords, one JSON value holding each one's name, the doors it is scoped to, its scrypt hash and its last use. Withheld from every read.", sensitive: true})
  stsAppPassword?: DirectoryJson;
  @attr(#{kind: "single", what: "The scrypt hash of a pending password reset link an administrator or the person started. Withheld from every read.", sensitive: true})
  stsPasswordResetToken?: string;
  @attr(#{kind: "single", what: "The person's Kerberos long-term keys for every encryption type, derived from their password, as one sealed value. Password-equivalent, so withheld from every read, ciphertext included.", sensitive: true})
  stsKrb5Keys?: string;
  @attr(#{kind: "multi", what: "The SIOPv2 self-issued subjects the person enrolled, one JSON value per subject: a DID or a JWK thumbprint URI, its label and who enrolled it. Whoever holds the key signs in as the person, so it is withheld from every read.", sensitive: true})
  stsSelfIssuedSubject?: (DirectoryJson)[];
  @attr(#{kind: "multi", what: "Each did:web this realm publishes for the person, one JSON value per DID: its id, the DID, who holds its key, every version of its keys, its deactivation and, in realm custody, the sealed private key. Withheld from every read.", sensitive: true})
  stsPublishedDid?: (DirectoryJson)[];
  @attr(#{kind: "single", what: "The scrypt hash of the CIBA user code the person set on /portal/ciba. Withheld from every read.", sensitive: true})
  stsCibaUserCode?: string;
  @attr(#{kind: "multi"})
  x509subject?: (DirectoryDn)[];
  @attr(#{kind: "multi"})
  x509issuer?: (DirectoryDn)[];
  @attr(#{kind: "multi"})
  x509serialNumber?: (string)[];
  @attr(#{kind: "multi"})
  x509notBefore?: (string)[];
  @attr(#{kind: "multi"})
  x509notAfter?: (string)[];
  @attr(#{kind: "multi"})
  x509fingerprint256?: (string)[];
  @attr(#{kind: "single"})
  x509svidsIssued?: DirectoryInteger;
  @attr(#{kind: "single"})
  x509firstIssued?: DirectoryTime;
  @attr(#{kind: "single"})
  x509lastIssued?: DirectoryTime;
  @attr(#{kind: "multi"})
  didSubject?: (string)[];
  @attr(#{kind: "multi"})
  didMethod?: (string)[];
  @attr(#{kind: "multi"})
  spiffeSubject?: (string)[];
  @attr(#{kind: "single"})
  spiffePath?: string;
  @attr(#{kind: "single"})
  spiffeTrustDomain?: string;
  @attr(#{kind: "single"})
  spiffeCredentialStatus?: string;
  @attr(#{kind: "single"})
  spiffeCredentialStatusReason?: string;
  @attr(#{kind: "single"})
  spiffeRevokedAt?: DirectoryTime;
  @attr(#{kind: "multi"})
  authnMethod?: (string)[];
  @attr(#{kind: "single"})
  mfaAuthenticated?: DirectoryBoolean;
  @attr(#{kind: "single"})
  mfaLastAuthTime?: DirectoryTime;
  @attr(#{kind: "multi"})
  federationIssuer?: (string)[];
  @attr(#{kind: "multi"})
  federationLink?: (string)[];
  @attr(#{kind: "single"})
  federationLastSeen?: DirectoryTime;
  @attr(#{kind: "multi"})
  federationAttribute?: (string)[];
  @attr(#{kind: "single"})
  stsProvisionedBy?: string;
  @attr(#{kind: "multi"})
  oauthConsent?: (string)[];
  @attr(#{kind: "multi"})
  oauthConsentWithdrawn?: (string)[];
  @attr(#{kind: "multi"})
  oauthConsentApplied?: (string)[];
  @attr(#{kind: "multi"})
  stsAndroidAttestedCredential?: (string)[];
  @attr(#{kind: "single"})
  stsWebauthnUserHandle?: DirectoryBase64;
  @attr(#{kind: "single"})
  stsWebauthnPqcUserHandle?: DirectoryBase64;
  @attr(#{kind: "single"})
  stsBootstrapAdministrator?: DirectoryBoolean;
  @attr(#{kind: "single"})
  stsConsoleClaimedAt?: DirectoryTime;
  @attr(#{kind: "single"})
  stsMfaRequired?: DirectoryBoolean;
  @attr(#{kind: "single"})
  stsNotDelegated?: DirectoryBoolean;
  @attr(#{kind: "single"})
  stsMayAct?: string;
  @attr(#{kind: "multi"})
  stsDelegationSemantics?: (string)[];
  @attr(#{kind: "single"})
  stsDefaultDelegationSemantics?: string;
  @attr(#{kind: "single"})
  stsMailVerified?: string;
  @attr(#{kind: "single"})
  stsMailVerifyToken?: string;
  @attr(#{kind: "single"})
  stsMailVerifyExpires?: DirectoryTime;
  @attr(#{kind: "single"})
  stsMailVerifyAddress?: string;
  @attr(#{kind: "multi"})
  stsPseudonym?: (string)[];
  @attr(#{kind: "single"})
  stsPseudonymVerifyToken?: string;
  @attr(#{kind: "single"})
  stsPseudonymVerifyExpires?: DirectoryTime;
  @attr(#{kind: "single"})
  stsPseudonymVerifyAddress?: string;
  @attr(#{kind: "multi"})
  stsAuthzenApplication?: (string)[];
  @attr(#{kind: "multi"})
  stsAuthzenCallbackUri?: (string)[];
  @attr(#{kind: "multi"})
  stsAssertionIssuer?: (string)[];
  @attr(#{kind: "multi"})
  stsAssertionKeyPair?: (DirectoryJson)[];
  @attr(#{kind: "multi"})
  stsAssertionPrivateKey?: (string)[];
  @attr(#{kind: "multi"})
  stsSamlAssertionIssuer?: (string)[];
  @attr(#{kind: "multi"})
  stsSamlAssertionKeyPair?: (DirectoryJson)[];
  @attr(#{kind: "multi"})
  stsSamlAssertionPrivateKey?: (string)[];
  @attr(#{kind: "multi"})
  stsEnrolledCertificate?: (DirectoryJson)[];
  @attr(#{kind: "multi"})
  stsEnrolledPrivateKey?: (string)[];
  @attr(#{kind: "multi"})
  stsAcmeEabKey?: (DirectoryJson)[];
  @attr(#{kind: "multi"})
  stsScepChallenge?: (DirectoryJson)[];
  @attr(#{kind: "multi"})
  stsCertificateHostName?: (string)[];
  @attr(#{kind: "single"})
  stsIdaVerification?: DirectoryJson;
  @attr(#{kind: "multi"})
  stsAudSub?: (string)[];
  @attr(#{kind: "single"})
  stsClaimSourceTokens?: DirectoryJson;
}
