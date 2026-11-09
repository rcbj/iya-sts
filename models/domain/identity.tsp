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
}
