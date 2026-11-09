// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/operational.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "operational",
  source: "catalogue",
  container: "",
  ownContainer: true,
  authored: true,
  section: "docs/ldap-schema.md Operational attributes",
  note: "Returned or computed for an entry. Not a container.",
  objectClasses: #[]
})
model Operational {
  @attr(#{what: "RFC 4530. Assigned at creation and kept through a rename."})
  entryUUID?: string;
  @attr(#{what: "RFC 4512 generalized time."})
  createTimestamp?: string;
  @attr(#{what: "RFC 4512 generalized time."})
  modifyTimestamp?: string;
  @attr(#{what: "RFC 5020. Computed at search time."})
  entryDN?: string;
  @attr(#{what: "The losing entryUUID of a two-process create race."})
  stsEntryUuidAlias?: (string)[];
  @attr(#{what: "A person's groups, derived from member. Never stored."})
  memberOf?: (DirectoryDn)[];
}
