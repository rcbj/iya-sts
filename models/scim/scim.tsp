// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/scim/scim.tsp
//
// Written by hand (#1579). THE SOURCE OF WHAT /scim/v2 PUBLISHES AND STORES:
// every schema /Schemas lists, every resource type /ResourceTypes lists, and
// the attribute mapping `scim/scim_map.ts` turns an entry into a resource
// with, and a resource or a PATCH back into directory changes.
// `models/tools/generate.mjs` compiles it into `models/generated/scim.json`
// during the image build. `scim/scim.ts` builds scimmy's definitions from
// that file, so the coercion that checks every POST, PUT and PATCH body is
// this model too.
//
// Each property is one attribute of RFC 7643 section 2. Its TypeSpec type
// says the attribute's type, whether it is multi-valued (an array), whether
// it is required (not optional), its sub-attributes (a model) and its
// canonical values (string literals); `@scimAttribute` says the rest of
// section 2.2, and `@maps` the directory attribute it is kept in. The
// descriptions are scimmy's, which are RFC 7643 section 8.7.1's, so that
// /Schemas reads as it always did.
//
// THE SCHEMAS SAY WHAT THE DIRECTORY HOLDS, AND NOTHING MORE (#206). A member
// of RFC 7643's schemas this directory has no place for is not written here:
// `nickName`, `locale`, `timezone`, `ims`, `photos`, `entitlements`, `roles`,
// `x509Certificates`, `name.middleName`, `name.honorificSuffix`,
// `costCenter`, `manager.displayName`, every `display` and `primary` of a
// multi-valued member, and a Group member's `display`. Until #1579 they were
// truncated off scimmy's copy at start; writing a row for one is how it comes
// back. `scim/CLAUDE.md` says why each went. `password` stays, write-only and
// never returned, so that a provisioning client sending one is not refused;
// it is not stored.
//
// A `type` lists only the types a row stores (`work`; `work` and `mobile`;
// `work`), which RFC 7643 section 2.3.1 allows, and the build refuses a type
// with no row. `schemas` is returned always (RFC 7643 section 3), where
// scimmy said `default`.

import "../lib/scim_lib.tsp";

using IyaSts.ScimLib;

@scimOwnTypes(#{
  plain: "this service's own (no standard type)",
  claims: "this service's own (#128; no standard type)",
  federation: "this service's own (#109; no standard type)"
})
namespace IyaSts.Scim;

// THE COMMON ATTRIBUTES (RFC 7643 section 3.1), on every resource and never
// listed in /Schemas. A core schema's are these; an extension's are scimmy's
// own, which nothing reads.
@scimCommon
model CommonAttributes {
  @scimAttribute(#{
    returned: "always",
    referenceTypes: #["uri"]
  })
  `schemas`?: ScimReference[];

  @scimAttribute(#{
    mutability: "readOnly",
    returned: "always",
    uniqueness: "global",
    caseExact: true,
    direction: "out"
  })
  `id`: string;

  @scimAttribute(#{
    caseExact: true
  })
  @maps(#{
    table: "user",
    row: 2,
    ldap: "scimExternalId",
    kind: "single",
    own: "plain",
    note: "The provisioning client's own identifier for this person. Stored verbatim and read by nothing here."
  })
  @maps(#{
    table: "group",
    row: 2,
    ldap: "scimExternalId",
    kind: "single",
    own: "plain"
  })
  `externalId`?: string;

  @scimAttribute(#{
    mutability: "readOnly"
  })
  `meta`: ResourceMeta;
}

@scimSchema(#{
  id: "urn:ietf:params:scim:schemas:core:2.0:User",
  name: "User",
  description: "User Account",
  resource: true,
  extensions: #[
    #{schema: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", required: false},
    #{schema: "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User", required: false},
    #{schema: "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:CustomAttributes", required: false}
  ]
})
model User {
  @scimAttribute(#{
    description: "Unique identifier for the User, typically used by the user to directly authenticate to the service provider. Each User MUST include a non-empty userName value. This identifier MUST be unique across the service provider's entire set of Users. REQUIRED.",
    uniqueness: "server",
    section: "RFC 7643 section 4.1.1"
  })
  @maps(#{
    table: "user",
    row: 1,
    ldap: "uid",
    kind: "single",
    cite: "RFC 4519 2.39",
    note: "The SCIM uniqueness constraint. It is the RDN of an auto-created entry, so for anybody this service authenticated it is also their sign-in name — but it is NOT the SCIM id, which is the entry's entryUUID."
  })
  `userName`: string;

  @scimAttribute(#{
    description: "The components of the user's real name. Providers MAY return just the full name as a single string in the formatted sub-attribute, or they MAY return just the individual component attributes using the other sub-attributes, or they MAY return both. If both variants are returned, they SHOULD be describing the same name, with the formatted name indicating how the component attributes should be combined."
  })
  `name`?: UserName;

  @scimAttribute(#{
    description: "The name of the User, suitable for display to end-users. The name SHOULD be the full name of the User being described, if known."
  })
  @maps(#{
    table: "user",
    row: 6,
    ldap: "displayName",
    kind: "single",
    cite: "RFC 2798 2.3"
  })
  `displayName`?: string;

  @scimAttribute(#{
    description: "A fully qualified URL pointing to a page representing the User's online profile.",
    referenceTypes: #["external"]
  })
  @maps(#{
    table: "user",
    row: 11,
    ldap: "labeledURI",
    kind: "single",
    cite: "RFC 2079 2"
  })
  `profileUrl`?: ScimReference;

  @scimAttribute(#{
    description: "The user's title, such as 'Vice President'."
  })
  @maps(#{
    table: "user",
    row: 7,
    ldap: "title",
    kind: "single",
    cite: "RFC 4519 2.38"
  })
  `title`?: string;

  @scimAttribute(#{
    description: "Used to identify the relationship between the organization and the user. Typical values used might be 'Contractor', 'Employee', 'Intern', 'Temp', 'External', and 'Unknown', but any value may be used."
  })
  @maps(#{
    table: "user",
    row: 9,
    ldap: "employeeType",
    kind: "single",
    cite: "RFC 2798 2.5"
  })
  `userType`?: string;

  @scimAttribute(#{
    description: "Indicates the User's preferred written or spoken language. Generally used for selecting a localized user interface; e.g. 'en_US' specifies the language English and country US."
  })
  @maps(#{
    table: "user",
    row: 10,
    ldap: "preferredLanguage",
    kind: "single",
    cite: "RFC 2798 2.10"
  })
  `preferredLanguage`?: string;

  @scimAttribute(#{
    description: "A Boolean value indicating the User's administrative status."
  })
  @maps(#{
    table: "user",
    row: 12,
    ldap: "pwdAccountLockedTime",
    kind: "lock",
    cite: "draft-behera-ldap-password-policy 5.3.3 (inverted)",
    note: "DISABLES THE ACCOUNT. false writes the administrative lock 000001010000Z and ends everything the person holds; every door then refuses them. true removes it. Not sent: unchanged."
  })
  `active`?: boolean;

  @scimAttribute(#{
    description: "The User's cleartext password. This attribute is intended to be used as a means to specify an initial password when creating a new User or to reset an existing User's password.",
    mutability: "writeOnly",
    returned: "never"
  })
  `password`?: string;

  @scimAttribute(#{
    description: "Email addresses for the user. The value SHOULD be canonicalized by the service provider, e.g. 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'."
  })
  @maps(#{
    table: "user",
    row: 13,
    ldap: "mail",
    kind: "multi",
    type: "work",
    cite: "RFC 4524 2.16"
  })
  `emails`?: UserEmail[];

  @scimAttribute(#{
    description: "Phone numbers for the User. The value SHOULD be canonicalized by the service provider according to the format specified in RFC 3966, e.g. 'tel:+1-201-555-0123'. Canonical type values of 'work', 'home', 'mobile', 'fax', 'pager', and 'other'.",
    uniqueness: "unpublished"
  })
  @maps(#{
    table: "user",
    row: 14,
    ldap: "telephoneNumber",
    kind: "multi",
    type: "work",
    cite: "RFC 4519 2.35"
  })
  @maps(#{
    table: "user",
    row: 15,
    ldap: "mobile",
    kind: "multi",
    type: "mobile",
    cite: "RFC 4524 2.18"
  })
  `phoneNumbers`?: UserPhoneNumber[];

  @scimAttribute(#{
    description: "A physical mailing address for this User. Canonical type values of 'work', 'home', and 'other'. This attribute is a complex type with the following sub-attributes."
  })
  `addresses`?: UserAddress[];

  @scimAttribute(#{
    description: "A list of groups to which the user belongs, either through direct membership, through nested groups, or dynamically calculated.",
    mutability: "readOnly",
    uniqueness: "unpublished",
    direction: "out"
  })
  @maps(#{
    table: "user",
    row: 36,
    ldap: "(member, uniqueMember, memberUid on the group)",
    kind: "derived",
    cite: "RFC 4519 2.17, 2.40; RFC 2307 2.3",
    note: "READ-ONLY, as RFC 7643 section 4.1.2 requires. Membership is a fact about the GROUP's entry, so it is changed through a Group resource and never through a User one. Resolved by ldap_server.js's groupsOfUser(), which is the same function the groups claim reads — so a token and a SCIM resource cannot disagree about who is in what."
  })
  `groups`?: UserGroup[];
}

@scimSchema(#{
  id: "urn:ietf:params:scim:schemas:core:2.0:Group",
  name: "Group",
  description: "Group",
  resource: true
})
model Group {
  @scimAttribute(#{
    description: "A human-readable name for the Group. REQUIRED.",
    section: "RFC 7643 section 4.2"
  })
  @maps(#{
    table: "group",
    row: 1,
    ldap: "cn",
    kind: "single",
    cite: "RFC 4519 2.3"
  })
  `displayName`: string;

  @scimAttribute(#{
    description: "A list of members of the Group.",
    uniqueness: "unpublished"
  })
  @maps(#{
    table: "group",
    row: 3,
    ldap: "member",
    kind: "members",
    cite: "RFC 4519 2.17",
    alsoClears: #["uniqueMember", "memberUid"],
    note: "READ resolves member, uniqueMember and memberUid alike; WRITE puts a new value in `member`, since a SCIM member id is a DN. A dangling member — a DN nothing is stored at — is returned as a member, because the group saying so is the fact, and this directory does no referential integrity on purpose."
  })
  `members`?: GroupMember[];
}

@scimSchema(#{
  id: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
  name: "EnterpriseUser",
  description: "Enterprise User",
  shipped: true
})
model EnterpriseUser {
  @scimAttribute(#{
    description: "Numeric or alphanumeric identifier assigned to a person, typically based on order of hire or association with an organization."
  })
  @maps(#{
    table: "user",
    row: 22,
    ldap: "employeeNumber",
    kind: "single",
    cite: "RFC 2798 2.6"
  })
  `employeeNumber`?: string;

  @scimAttribute(#{
    description: "Identifies the name of an organization."
  })
  @maps(#{
    table: "user",
    row: 24,
    ldap: "o",
    kind: "single",
    cite: "RFC 4519 2.19"
  })
  `organization`?: string;

  @scimAttribute(#{
    description: "Identifies the name of a division."
  })
  @maps(#{
    table: "user",
    row: 25,
    ldap: "ou",
    kind: "single",
    cite: "RFC 4519 2.20"
  })
  `division`?: string;

  @scimAttribute(#{
    description: "Identifies the name of a department."
  })
  @maps(#{
    table: "user",
    row: 23,
    ldap: "departmentNumber",
    kind: "single",
    cite: "RFC 2798 2.4"
  })
  `department`?: string;

  @scimAttribute(#{
    description: "The User's manager.  A complex type that optionally allows service providers to represent organizational hierarchy by referencing the 'id' attribute of another User.",
    uniqueness: "unpublished"
  })
  `manager`?: EnterpriseManager;
}

@scimSchema(#{
  id: "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User",
  name: "IyaStsUser",
  description: "This service's own User extension: which federation partners' subjects are linked to the person, and the Identity Assurance claims no standard schema carries (#128)."
})
model IyaStsUser {
  @scimAttribute(#{
    description: "A formal salutation, e.g. \"Ms\" (the Claims Registration's salutation)."
  })
  @maps(#{
    table: "user",
    row: 27,
    ldap: "salutation",
    kind: "single",
    own: "claims"
  })
  `salutation`?: string;

  @scimAttribute(#{
    description: "The family name at birth."
  })
  @maps(#{
    table: "user",
    row: 28,
    ldap: "birthFamilyName",
    kind: "single",
    own: "claims"
  })
  `birthFamilyName`?: string;

  @scimAttribute(#{
    description: "The given name at birth."
  })
  @maps(#{
    table: "user",
    row: 29,
    ldap: "birthGivenName",
    kind: "single",
    own: "claims"
  })
  `birthGivenName`?: string;

  @scimAttribute(#{
    description: "The middle name at birth."
  })
  @maps(#{
    table: "user",
    row: 30,
    ldap: "birthMiddleName",
    kind: "single",
    own: "claims"
  })
  `birthMiddleName`?: string;

  @scimAttribute(#{
    description: "Another name the person is known by, e.g. a stage name."
  })
  @maps(#{
    table: "user",
    row: 31,
    ldap: "alsoKnownAs",
    kind: "single",
    own: "claims"
  })
  `alsoKnownAs`?: string;

  @scimAttribute(#{
    description: "The country of birth, ISO 3166-1 alpha-2."
  })
  @maps(#{
    table: "user",
    row: 32,
    ldap: "placeOfBirthCountry",
    kind: "single",
    own: "claims"
  })
  `placeOfBirthCountry`?: string;

  @scimAttribute(#{
    description: "The region of birth."
  })
  @maps(#{
    table: "user",
    row: 33,
    ldap: "placeOfBirthRegion",
    kind: "single",
    own: "claims"
  })
  `placeOfBirthRegion`?: string;

  @scimAttribute(#{
    description: "The locality of birth."
  })
  @maps(#{
    table: "user",
    row: 34,
    ldap: "placeOfBirthLocality",
    kind: "single",
    own: "claims"
  })
  `placeOfBirthLocality`?: string;

  // WHERE A NEW PERSON IS HOMED (#98 D1), in a service deployed as cells:
  // the cell id, on a create only. Write-only and never returned — a cell is
  // a routing fact nothing a client reads may name — and never stored on the
  // entry: the entry existing in that cell IS the home, so it has no row. An
  // update naming another cell is refused (re-homing is an administrator's
  // act); a single-cell service ignores it. `scim/scim_cells.ts` reads it.
  @scimAttribute(#{
    description: "On a create in a service deployed as several regions: the region the person is homed in, whose data stays there. The realm's default when not sent. Never returned, and not changed by a later write.",
    mutability: "writeOnly",
    returned: "never",
    caseExact: true
  })
  `homeCell`?: string;

  @scimAttribute(#{
    description: "Each a federation partner's identifier for the person, through one service-provider-side relationship. Not sent: unchanged. Sent: replaced; a link removed ends the sessions that partner signed the person in to."
  })
  @maps(#{
    table: "user",
    row: 35,
    ldap: "federationLink",
    kind: "links",
    own: "federation",
    note: "Which federation partners' subjects sign this person in, each { relationship, issuer, subject } — issuer optional on the way in, the relationship's fedPeer. NOT SENT: unchanged, so a provisioning client that knows nothing of this extension cannot unlink anybody by leaving it out. Sent, even empty: replaced, and every link removed ends the sessions that partner signed the person in to. A link another person carries is refused 409."
  })
  `federationLinks`?: FederationLink[];
}

@scimSchema(#{
  id: "urn:ietf:params:scim:schemas:extension:iya-sts:2.0:CustomAttributes",
  name: "CustomAttributes",
  description: "This realm's custom attributes, as its administrators define them on Directory → Policies → Attribute policy. Each realm has its own; not sent on a PUT, they are left as they are.",
  realmDefined: true
})
model CustomAttributes {
}

model ResourceMeta {
  @scimAttribute(#{
    mutability: "readOnly",
    caseExact: true
  })
  `resourceType`: string;

  @scimAttribute(#{
    mutability: "readOnly",
    direction: "out"
  })
  @maps(#{
    table: "user",
    row: 37,
    ldap: "createTimestamp",
    kind: "derived",
    cite: "RFC 4512 3.4"
  })
  @maps(#{
    table: "group",
    row: 4,
    ldap: "createTimestamp",
    kind: "derived",
    cite: "RFC 4512 3.4"
  })
  `created`?: utcDateTime;

  @scimAttribute(#{
    mutability: "readOnly",
    direction: "out"
  })
  @maps(#{
    table: "user",
    row: 38,
    ldap: "modifyTimestamp",
    kind: "derived",
    cite: "RFC 4512 3.4"
  })
  @maps(#{
    table: "group",
    row: 5,
    ldap: "modifyTimestamp",
    kind: "derived",
    cite: "RFC 4512 3.4"
  })
  `lastModified`?: utcDateTime;

  @scimAttribute(#{
    mutability: "readOnly",
    direction: "out"
  })
  `location`?: string;

  @scimAttribute(#{
    mutability: "readOnly",
    direction: "out"
  })
  `version`?: string;
}

model UserName {
  @scimAttribute(#{
    description: "The full name, including all middle names, titles, and suffixes as appropriate, formatted for display (e.g. 'Ms. Barbara J Jensen, III')."
  })
  @maps(#{
    table: "user",
    row: 3,
    ldap: "cn",
    kind: "single",
    cite: "RFC 4519 2.3"
  })
  `formatted`?: string;

  @scimAttribute(#{
    description: "The family name of the User, or last name in most Western languages (e.g. 'Jensen' given the full name 'Ms. Barbara J Jensen, III')."
  })
  @maps(#{
    table: "user",
    row: 4,
    ldap: "sn",
    kind: "single",
    cite: "RFC 4519 2.32"
  })
  `familyName`?: string;

  @scimAttribute(#{
    description: "The given name of the User, or first name in most Western languages (e.g. 'Barbara' given the full name 'Ms. Barbara J Jensen, III')."
  })
  @maps(#{
    table: "user",
    row: 5,
    ldap: "givenName",
    kind: "single",
    cite: "RFC 4519 2.6"
  })
  `givenName`?: string;

  @scimAttribute(#{
    description: "The honorific prefix(es) of the User, or title in most Western languages (e.g. 'Ms.' given the full name 'Ms. Barbara J Jensen, III')."
  })
  // RFC 7643's honorific prefix — "title in most Western languages" — is the
  // Claims Registration's `title` (#128). SCIM's own `title` stays the JOB
  // title, which is what RFC 7643 section 4.1.1 means by it.
  @maps(#{
    table: "user",
    row: 8,
    ldap: "schacPersonalTitle",
    kind: "single",
    cite: "SCHAC 1.5.0"
  })
  `honorificPrefix`?: string;
}

model UserEmail {
  @scimAttribute(#{
    description: "Email addresses for the user. The value SHOULD be canonicalized by the service provider, e.g. 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'."
  })
  `value`?: string;

  @scimAttribute(#{
    description: "A label indicating the attribute's function, e.g. 'work' or 'home'."
  })
  `type`?: "work";
}

model UserPhoneNumber {
  @scimAttribute(#{
    description: "Phone number of the User."
  })
  `value`?: string;

  @scimAttribute(#{
    description: "A label indicating the attribute's function, e.g. 'work', 'home', 'mobile'."
  })
  `type`?: "work" | "mobile";
}

model UserAddress {
  @scimAttribute(#{
    description: "The full mailing address, formatted for display or use with a mailing label. This attribute MAY contain newlines."
  })
  @maps(#{
    table: "user",
    row: 21,
    ldap: "postalAddress",
    kind: "complex",
    cite: "RFC 4519 2.23",
    transform: "postalAddress"
  })
  `formatted`?: string;

  @scimAttribute(#{
    description: "The full street address component, which may include house number, street name, P.O. box, and multi-line extended street address information. This attribute MAY contain newlines."
  })
  @maps(#{
    table: "user",
    row: 16,
    ldap: "street",
    kind: "complex",
    cite: "RFC 4519 2.34"
  })
  `streetAddress`?: string;

  @scimAttribute(#{
    description: "The city or locality component."
  })
  @maps(#{
    table: "user",
    row: 17,
    ldap: "l",
    kind: "complex",
    cite: "RFC 4519 2.16"
  })
  `locality`?: string;

  @scimAttribute(#{
    description: "The state or region component."
  })
  @maps(#{
    table: "user",
    row: 18,
    ldap: "st",
    kind: "complex",
    cite: "RFC 4519 2.33"
  })
  `region`?: string;

  @scimAttribute(#{
    description: "The zip code or postal code component."
  })
  @maps(#{
    table: "user",
    row: 19,
    ldap: "postalCode",
    kind: "complex",
    cite: "RFC 4519 2.24"
  })
  `postalCode`?: string;

  @scimAttribute(#{
    description: "The country name component."
  })
  @maps(#{
    table: "user",
    row: 20,
    ldap: "c",
    kind: "complex",
    cite: "RFC 4519 2.2"
  })
  `country`?: string;

  @scimAttribute(#{
    description: "A label indicating the attribute's function, e.g. 'work' or 'home'."
  })
  `type`?: "work";
}

model UserGroup {
  @scimAttribute(#{
    description: "The identifier of the User's group.",
    mutability: "readOnly",
    direction: "out"
  })
  `value`?: string;

  @scimAttribute(#{
    description: "The URI of the corresponding 'Group' resource to which the user belongs.",
    mutability: "readOnly",
    referenceTypes: #["User", "Group"],
    direction: "out"
  })
  `$ref`?: ScimReference;

  @scimAttribute(#{
    description: "A human-readable name, primarily used for display purposes. READ-ONLY.",
    mutability: "readOnly",
    direction: "out"
  })
  `display`?: string;

  @scimAttribute(#{
    description: "A label indicating the attribute's function, e.g. 'direct' or 'indirect'.",
    mutability: "readOnly",
    direction: "out"
  })
  `type`?: "direct" | "indirect";
}

model GroupMember {
  @scimAttribute(#{
    description: "Identifier of the member of this Group.",
    mutability: "immutable"
  })
  `value`?: string;

  @scimAttribute(#{
    description: "The URI corresponding to a SCIM resource that is a member of this Group.",
    mutability: "immutable",
    referenceTypes: #["User", "Group"]
  })
  `$ref`?: ScimReference;

  @scimAttribute(#{
    description: "A label indicating the type of resource, e.g., 'User' or 'Group'.",
    mutability: "immutable"
  })
  `type`?: "User" | "Group";
}

model EnterpriseManager {
  @scimAttribute(#{
    description: "The id of the SCIM resource representing the User's manager."
  })
  @maps(#{
    table: "user",
    row: 26,
    ldap: "manager",
    kind: "single",
    cite: "RFC 2798 2.9",
    note: "A DN in the directory and an id in SCIM, translated both ways by the SCIM handlers since the id became the entryUUID (2026-09-14). A value naming no entry is kept as it was sent."
  })
  `value`?: string;

  @scimAttribute(#{
    description: "The URI of the SCIM resource representing the User's manager.",
    referenceTypes: #["User"]
  })
  `$ref`?: ScimReference;
}

model FederationLink {
  @scimAttribute(#{
    description: "The service-provider-side relationship.",
    caseExact: true
  })
  `relationship`: string;

  @scimAttribute(#{
    description: "The partner's entity ID or iss; the relationship's fedPeer when omitted.",
    caseExact: true
  })
  `issuer`?: string;

  @scimAttribute(#{
    description: "The partner's stable identifier for the person (an OpenID Connect sub, a SAML persistent NameID).",
    caseExact: true
  })
  `subject`: string;
}
