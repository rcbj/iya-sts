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
